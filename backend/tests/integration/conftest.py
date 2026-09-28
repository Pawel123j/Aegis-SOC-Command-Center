"""Explicit opt-in, real services and a fresh, owner-created database for every test.

Run with AEGIS_INTEGRATION_TESTS=1 and the Compose tests service environment.
Missing services/configuration fail selected integration tests; nothing is silently skipped.
The owner DSN is used only to create/drop a generated database and to migrate that database.
Redis keys use database 1 and unique client/session identities, and expire after 60 seconds.
No existing PostgreSQL tables or Redis keys are ever truncated, flushed or deleted.
"""

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr
from redis import Redis
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.bootstrap import bootstrap_admin
from app.core.config import Settings
from app.core.security import random_token

from .helpers import Case, IsolatedDatabase, Login, migrate


@dataclass(repr=False)
class Services:
    settings: Settings
    owner_url: URL
    broker_url: SecretStr


@pytest.fixture(scope="session")
def services() -> Services:
    if os.environ.get("AEGIS_INTEGRATION_TESTS") != "1":
        pytest.fail("Integration tests require AEGIS_INTEGRATION_TESTS=1", pytrace=False)
    if not os.environ.get("AEGIS_TEST_DATABASE_URL"):
        pytest.fail("Integration tests require owner AEGIS_TEST_DATABASE_URL", pytrace=False)
    try:
        settings = Settings()
        owner = make_url(os.environ["AEGIS_TEST_DATABASE_URL"])
        Settings.validate_database_url(SecretStr(owner.render_as_string(hide_password=False)))
        runtime = make_url(settings.database_url.get_secret_value())
        if runtime.username != "aegis_app":
            raise ValueError("runtime role")
        if (owner.host, owner.port) != (runtime.host, runtime.port):
            raise ValueError("PostgreSQL host mismatch")
    except Exception:
        pytest.fail(
            "Invalid integration service configuration (credentials omitted)", pytrace=False
        )

    # These are authenticated, bounded probes; all tests depend on real infrastructure.
    engine = create_engine(owner, poolclass=NullPool, connect_args={"connect_timeout": 3})
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT 1")) == 1
            assert connection.scalar(text("SELECT 1 FROM pg_roles WHERE rolname='aegis_app'")) == 1
    except Exception:
        pytest.fail("PostgreSQL owner connection or aegis_app role unavailable", pytrace=False)
    finally:
        engine.dispose()
    try:
        with Redis.from_url(
            settings.redis_url.get_secret_value(), socket_connect_timeout=2, socket_timeout=2
        ) as redis:
            assert redis.ping()
    except Exception:
        pytest.fail("Authenticated Redis service unavailable", pytrace=False)
    try:
        with httpx.Client(
            auth=(settings.clickhouse_user, settings.clickhouse_password.get_secret_value()),
            timeout=2,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = client.post(settings.clickhouse_url, content="SELECT 1")
            assert response.status_code == 200 and response.text.strip() == "1"
    except Exception:
        pytest.fail("Authenticated ClickHouse service unavailable", pytrace=False)
    return Services(settings, owner, settings.redis_url)


@pytest.fixture
def isolated_database(services: Services) -> Iterator[IsolatedDatabase]:
    name = f"aegis_test_{uuid4().hex}"
    assert re.fullmatch(r"aegis_test_[0-9a-f]{32}", name)
    control = create_engine(
        services.owner_url,
        isolation_level="AUTOCOMMIT",
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"connect_timeout": 3},
    )
    owner = create_engine(
        services.owner_url.set(database=name),
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"connect_timeout": 3},
    )
    runtime_url = make_url(services.settings.database_url.get_secret_value()).set(database=name)
    runtime = create_engine(runtime_url, poolclass=NullPool, hide_parameters=True)
    created: set[str] = set()
    quoted = control.dialect.identifier_preparer.quote(name)
    try:
        with control.connect() as connection:
            connection.execute(text(f"CREATE DATABASE {quoted}"))
            created.add(name)
            connection.execute(text(f"REVOKE ALL ON DATABASE {quoted} FROM PUBLIC"))
            connection.execute(text(f"GRANT CONNECT ON DATABASE {quoted} TO aegis_app"))
        with owner.connect() as connection:
            assert connection.scalar(text("SELECT current_database()")) == name
        migrate(owner)
        redis_url = urlsplit(services.settings.redis_url.get_secret_value())
        settings = services.settings.model_copy(
            update={
                "database_url": SecretStr(runtime_url.render_as_string(hide_password=False)),
                "redis_url": SecretStr(urlunsplit(redis_url._replace(path="/1"))),
                "jwt_secret": SecretStr(random_token()),
                "public_origin": "http://localhost:8080",
                "local_http": True,
            }
        )
        yield IsolatedDatabase(name, owner, runtime, settings)
    finally:
        runtime.dispose()
        owner.dispose()
        try:
            if name in created:
                # Never clean up a pre-existing DB, a user-supplied name or an application DB.
                assert re.fullmatch(r"aegis_test_[0-9a-f]{32}", name)
                with control.connect() as connection:
                    connection.execute(text(f"DROP DATABASE {quoted} WITH (FORCE)"))
                created.remove(name)
        finally:
            control.dispose()


@pytest.fixture
def case(isolated_database: IsolatedDatabase) -> Iterator[Case]:
    scenario = Case(isolated_database)
    try:
        yield scenario
    finally:
        scenario.stack.close()


@pytest.fixture
def admin(case: Case) -> Login:
    password = random_token()
    with Session(case.database.runtime) as session:
        bootstrap_admin(session, "initial_admin", password)
    return case.login("initial_admin", password)
