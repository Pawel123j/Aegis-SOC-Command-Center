"""Real PostgreSQL migration, privilege and transaction guarantees."""

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.bootstrap import BootstrapRefused, bootstrap_admin
from app.core.security import random_token
from app.infrastructure.database import Base
from app.modules.audit.models import AuditLog
from app.modules.users.models import User

from .helpers import Case, IsolatedDatabase, Login, migrate

pytestmark = pytest.mark.integration


def test_bootstrap_is_one_time_and_audited(isolated_database: IsolatedDatabase) -> None:
    with Session(isolated_database.runtime) as session:
        created = bootstrap_admin(session, "INITIAL_ADMIN", random_token())
        assert created.username == "initial_admin" and created.role.value == "admin"
        with pytest.raises(BootstrapRefused):
            bootstrap_admin(session, "second_admin", random_token())
        assert session.scalar(select(func.count()).select_from(User)) == 1
        assert session.scalar(select(func.count()).select_from(AuditLog)) == 1
        assert session.scalar(select(AuditLog.action)) == "user.bootstrap"


def test_migrations_round_trip_and_match_models(isolated_database: IsolatedDatabase) -> None:
    for operation in ("initial", "downgrade", "reupgrade"):
        if operation == "downgrade":
            migrate(isolated_database.owner, "base", downgrade=True)
            assert not set(Base.metadata.tables) & set(
                inspect(isolated_database.owner).get_table_names()
            )
            continue
        if operation == "reupgrade":
            migrate(isolated_database.owner)
        with isolated_database.owner.connect() as connection:
            context = MigrationContext.configure(
                connection, opts={"compare_type": True, "compare_server_default": True}
            )
            assert compare_metadata(context, Base.metadata) == []
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "0009_sigma"
            )
        with isolated_database.runtime.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                "0009_sigma"
            )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_logs SET outcome = 'tampered'",
        "DELETE FROM audit_logs",
        "TRUNCATE audit_logs",
        "ALTER TABLE audit_logs ADD COLUMN tampered text",
        "DROP TABLE audit_logs",
        "CREATE TABLE unauthorized_table (id integer)",
    ],
)
def test_runtime_cannot_modify_audit_or_run_ddl(case: Case, admin: Login, statement: str) -> None:
    with case.database.runtime.connect() as connection:
        before = connection.scalar(text("SELECT count(*) FROM audit_logs"))
        assert before and before >= 2
        connection.rollback()
        with pytest.raises(DBAPIError) as rejected:
            connection.execute(text(statement))
        assert getattr(rejected.value.orig, "sqlstate", None) == "42501"
        connection.rollback()
        assert connection.scalar(text("SELECT count(*) FROM audit_logs")) == before


def test_failed_audit_insert_rolls_back_api_user_creation(case: Case, admin: Login) -> None:
    with case.database.owner.begin() as connection:
        connection.execute(text("REVOKE INSERT ON audit_logs FROM aegis_app"))
    try:
        response = admin.client.post(
            "/api/v1/users",
            json={"username": "must_rollback", "password": random_token(), "role": "read_only"},
            headers=admin.authorization,
        )
        assert response.status_code == 503
        assert response.json()["code"] == "dependency_unavailable"
    finally:
        with case.database.owner.begin() as connection:
            connection.execute(text("GRANT INSERT ON audit_logs TO aegis_app"))
    with Session(case.database.runtime) as session:
        assert session.scalar(select(User).where(User.username == "must_rollback")) is None
        assert session.scalar(select(AuditLog.id).where(AuditLog.action == "user.created")) is None
    # The restored permission permits the same operation, including its audit, to commit.
    case.create_user(admin)
    with Session(case.database.runtime) as session:
        assert session.scalar(select(func.count()).select_from(User)) == 2
        assert (
            session.scalar(
                select(func.count()).select_from(AuditLog).where(AuditLog.action == "user.created")
            )
            == 1
        )


def test_user_and_audit_pagination_do_not_repeat_or_expose_credentials(
    case: Case, admin: Login
) -> None:
    for _ in range(3):
        case.create_user(admin)
    for route in ("users", "audit"):
        cursor = None
        seen: set[str] = set()
        for _ in range(20):
            params = {"limit": "2"}
            if cursor:
                params["cursor"] = cursor
            response = admin.client.get(
                f"/api/v1/{route}", params=params, headers=admin.authorization
            )
            assert response.status_code == 200
            assert "password_hash" not in response.text and admin.password not in response.text
            page = response.json()
            identifiers = {row["id"] for row in page["items"]}
            assert not seen & identifiers
            seen.update(identifiers)
            cursor = page["next_cursor"]
            if cursor is None:
                break
        else:
            pytest.fail("Pagination did not terminate")
        assert len(seen) == (4 if route == "users" else 5)
