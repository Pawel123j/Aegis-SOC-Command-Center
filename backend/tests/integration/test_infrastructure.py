"""Live dependency probes and broker-to-worker-to-result acceptance check."""

import pytest
from celery import Celery
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.engine import make_url

from app.core.security import random_token

from .conftest import Services
from .helpers import Case, Login

pytestmark = pytest.mark.integration


def test_readiness_checks_real_dependencies_with_runtime_credentials(
    case: Case, admin: Login
) -> None:
    ready = admin.client.get("/ready")
    assert ready.status_code == 200 and ready.json() == {"status": "ready"}
    assert ready.headers["cache-control"] == "no-store"
    detail = admin.client.get("/api/v1/system/health", headers=admin.authorization)
    assert detail.status_code == 200
    assert detail.json() == {
        "status": "ready",
        "checks": {"postgresql": "ok", "migrations": "ok", "redis": "ok", "clickhouse": "ok"},
    }
    metrics = admin.client.get("/metrics")
    assert metrics.status_code == 200 and "aegis_http_requests_total" in metrics.text


@pytest.mark.parametrize("failure", ["postgresql", "migrations", "redis", "clickhouse"])
def test_real_dependency_failure_returns_only_aggregate_readiness(case: Case, failure: str) -> None:
    settings = case.database.settings
    updates: dict[str, object] = {}
    if failure == "postgresql":
        url = make_url(settings.database_url.get_secret_value()).set(password=random_token())
        updates["database_url"] = SecretStr(url.render_as_string(hide_password=False))
    elif failure == "redis":
        url = make_url(settings.redis_url.get_secret_value()).set(password=random_token())
        updates["redis_url"] = SecretStr(url.render_as_string(hide_password=False))
    elif failure == "clickhouse":
        updates["clickhouse_password"] = SecretStr(random_token())
    else:
        with case.database.owner.begin() as connection:
            connection.execute(text("UPDATE alembic_version SET version_num='unexpected_revision'"))
    client = case.client(settings.model_copy(update=updates))
    assert client.get("/health").json() == {"status": "ok"}
    response = client.get("/ready")
    assert response.status_code == 503 and response.json() == {"status": "not_ready"}
    assert response.headers["cache-control"] == "no-store"
    if failure == "redis":
        response = client.get("/api/v1/auth/csrf")
        assert response.status_code == 503
        assert response.json()["code"] == "limiter_unavailable"


def test_celery_ping_crosses_real_broker_worker_and_result_backend(services: Services) -> None:
    # Only this documented harmless task uses the worker's existing broker DB (normally 0).
    # Limiter tests use DB 1; no task arguments or application mutations are involved.
    broker = services.broker_url.get_secret_value()
    with Celery("aegis-integration", broker=broker, backend=broker) as client:
        client.conf.update(
            task_serializer="json",
            result_serializer="json",
            accept_content=["json"],
            result_accept_content=["json"],
            broker_connection_timeout=2,
            redis_socket_connect_timeout=2,
            redis_socket_timeout=2,
        )
        result = client.send_task("aegis.ping", retry=False)
        try:
            assert result.get(timeout=30) == "pong"
        finally:
            result.forget()
