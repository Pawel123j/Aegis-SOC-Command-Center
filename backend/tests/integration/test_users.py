"""Role enforcement, optimistic updates and immediate session revocation."""

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import random_token
from app.modules.audit.models import AuditLog
from app.modules.users.models import User

from .helpers import Case, Login

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    ("role", "users_status", "audit_status", "system_status"),
    [
        ("admin", 200, 200, 200),
        ("soc_manager", 403, 200, 200),
        ("soc_analyst", 403, 403, 403),
        ("read_only", 403, 403, 403),
    ],
)
def test_roles_are_enforced_on_real_endpoints(
    case: Case, admin: Login, role: str, users_status: int, audit_status: int, system_status: int
) -> None:
    user = case.create_user(admin, role)
    principal = case.login(str(user["username"]), str(user["password"]))
    for route, expected in (
        ("users", users_status),
        ("audit", audit_status),
        ("system/health", system_status),
    ):
        response = principal.client.get(f"/api/v1/{route}", headers=principal.authorization)
        assert response.status_code == expected
        assert "password_hash" not in response.text
    created = principal.client.post(
        "/api/v1/users",
        json={"username": "another_identity", "password": random_token(), "role": "read_only"},
        headers=principal.authorization,
    )
    assert created.status_code == (201 if role == "admin" else 403)
    changed = principal.client.patch(
        f"/api/v1/users/{admin.user_id}",
        json={"enabled": True},
        headers={**principal.authorization, "If-Match": '"1"'},
    )
    assert changed.status_code == (200 if role == "admin" else 403)
    if role != "admin":
        with Session(case.database.runtime) as session:
            assert (
                session.scalar(
                    select(AuditLog.id).where(AuditLog.action == "authorization.denied").limit(1)
                )
                is not None
            )


def test_user_patch_requires_current_version_and_normalized_names_are_unique(
    case: Case, admin: Login
) -> None:
    user = case.create_user(admin)
    path = f"/api/v1/users/{user['id']}"
    assert (
        admin.client.patch(
            path, json={"role": "read_only"}, headers=admin.authorization
        ).status_code
        == 428
    )
    updated = admin.client.patch(
        path, json={"role": "read_only"}, headers={**admin.authorization, "If-Match": '"1"'}
    )
    assert updated.status_code == 200 and updated.json()["version"] == 2
    assert updated.headers["etag"] == '"2"'
    stale = admin.client.patch(
        path, json={"enabled": False}, headers={**admin.authorization, "If-Match": '"1"'}
    )
    assert stale.status_code == 412
    duplicate = admin.client.post(
        "/api/v1/users",
        json={
            "username": str(user["username"]).upper(),
            "password": random_token(),
            "role": "read_only",
        },
        headers=admin.authorization,
    )
    assert duplicate.status_code == 409
    with Session(case.database.runtime) as session:
        stored = session.scalar(select(User).where(User.username == user["username"]))
        assert stored is not None and stored.enabled and stored.version == 2


def test_last_active_admin_cannot_be_disabled_or_demoted(case: Case, admin: Login) -> None:
    for change in ({"enabled": False}, {"role": "read_only"}):
        response = admin.client.patch(
            f"/api/v1/users/{admin.user_id}",
            json=change,
            headers={**admin.authorization, "If-Match": '"1"'},
        )
        assert response.status_code == 409
        assert response.json()["code"] == "last_admin"
    assert admin.client.get("/api/v1/auth/me", headers=admin.authorization).status_code == 200


@pytest.mark.parametrize("change", ["enabled", "role", "password"])
def test_sensitive_account_changes_revoke_all_existing_sessions(
    case: Case, admin: Login, change: str
) -> None:
    user = case.create_user(admin)
    sessions = [case.login(str(user["username"]), str(user["password"])) for _ in range(2)]
    value = {"enabled": False, "role": "read_only", "password": random_token()}[change]
    response = admin.client.patch(
        f"/api/v1/users/{user['id']}",
        json={change: value},
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert response.status_code == 200 and response.json()["version"] == 2
    for principal in sessions:
        assert (
            principal.client.get("/api/v1/auth/me", headers=principal.authorization).status_code
            == 401
        )
        assert (
            principal.client.post(
                "/api/v1/auth/refresh", headers=principal.mutation_headers
            ).status_code
            == 401
        )
    if change == "enabled":
        assert (
            admin.client.patch(
                f"/api/v1/users/{user['id']}",
                json={"enabled": True},
                headers={**admin.authorization, "If-Match": '"2"'},
            ).status_code
            == 200
        )
        assert (
            sessions[0].client.get("/api/v1/auth/me", headers=sessions[0].authorization).status_code
            == 401
        )
    fresh = case.login(
        str(user["username"]), str(value if change == "password" else user["password"])
    )
    identity = fresh.client.get("/api/v1/auth/me", headers=fresh.authorization).json()
    assert identity["role"] == ("read_only" if change == "role" else "soc_analyst")
