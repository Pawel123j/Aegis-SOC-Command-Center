"""Probe failure, log redaction and HTTP-boundary behavior without external services."""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.api import health
from app.core.observability import (
    REGISTRY,
    REQUEST_ID,
    ObservabilityMiddleware,
    SafeJSONFormatter,
)


class ScalarResult:
    def __init__(self, value: Any) -> None:
        self.value = value

    def scalar_one(self) -> Any:
        return self.value


class StubSession:
    def __init__(self, revision: str = health.EXPECTED_REVISION, fail: bool = False) -> None:
        self.revision = revision
        self.fail = fail

    def __enter__(self) -> StubSession:
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def execute(self, statement: Any) -> ScalarResult:
        if self.fail:
            raise RuntimeError("postgresql://user:private-db-password@internal/database")
        return ScalarResult(self.revision if "alembic_version" in str(statement) else 1)


@pytest.fixture
def probe_app(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        clickhouse_url="http://clickhouse:8123",
        clickhouse_user="runtime",
        clickhouse_password=SecretStr("private-clickhouse-password"),
        local_http=False,
    )
    app.state.database = SimpleNamespace(sessions=StubSession)
    app.state.redis = SimpleNamespace(ping=lambda: True)
    app.add_middleware(ObservabilityMiddleware)
    app.include_router(health.router)

    @app.get("/objects/{object_id}")
    def object_route(object_id: str, request: Request) -> dict[str, str]:
        return {"request_id": request.state.request_id}

    @app.get("/crash")
    def crash() -> None:
        raise RuntimeError("Authorization: Bearer private-access-token")

    monkeypatch.setattr(health, "_clickhouse_status", lambda request: "ok")
    return app


def test_liveness_and_ready(probe_app: FastAPI) -> None:
    with TestClient(probe_app) as client:
        assert client.get("/health").json() == {"status": "ok"}
        response = client.get("/ready")
        assert response.status_code == 200
        assert response.json() == {"status": "ready"}
        assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("failure", ["postgresql", "migrations", "redis", "clickhouse"])
def test_readiness_fails_closed_without_internal_detail(
    probe_app: FastAPI, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    if failure == "postgresql":
        probe_app.state.database.sessions = lambda: StubSession(fail=True)
    elif failure == "migrations":
        probe_app.state.database.sessions = lambda: StubSession(revision="unexpected")
    elif failure == "redis":
        probe_app.state.redis.ping = lambda: False
    else:
        monkeypatch.setattr(health, "_clickhouse_status", lambda request: "unavailable")
    with TestClient(probe_app) as client:
        response = client.get("/ready")
        assert response.status_code == 503
        assert response.json() == {"status": "not_ready"}
        assert "private-" not in response.text
        assert "internal" not in response.text
        assert client.get("/health").status_code == 200


@pytest.mark.parametrize("request_id", ["safe-id_012.abc", "x" * 64])
def test_request_id_is_preserved(probe_app: FastAPI, request_id: str) -> None:
    with TestClient(probe_app) as client:
        response = client.get("/objects/123", headers={"X-Request-ID": request_id})
        assert response.json()["request_id"] == request_id
        assert response.headers["x-request-id"] == request_id


@pytest.mark.parametrize("request_id", ["x" * 65, "a b", "<script>", "", "first,second"])
def test_invalid_request_id_is_replaced(probe_app: FastAPI, request_id: str) -> None:
    with TestClient(probe_app) as client:
        response = client.get("/objects/123", headers={"X-Request-ID": request_id})
        assigned = response.headers["x-request-id"]
        assert len(assigned) == 32
        assert assigned != request_id


def test_duplicate_request_id_headers_are_replaced(probe_app: FastAPI) -> None:
    with TestClient(probe_app) as client:
        response = client.get(
            "/health", headers=[("X-Request-ID", "first"), ("X-Request-ID", "second")]
        )
        assert response.headers["x-request-id"] not in {"first", "second"}


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_security_headers_use_actual_scheme(probe_app: FastAPI, scheme: str) -> None:
    with TestClient(probe_app, base_url=f"{scheme}://testserver") as client:
        response = client.get("/unknown", headers={"X-Forwarded-Proto": "https"})
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert ("strict-transport-security" in response.headers) == (scheme == "https")


def test_local_http_setting_disables_hsts(probe_app: FastAPI) -> None:
    probe_app.state.settings.local_http = True
    with TestClient(probe_app, base_url="https://testserver") as client:
        assert "strict-transport-security" not in client.get("/health").headers


def test_unhandled_error_is_safe_and_has_security_headers(probe_app: FastAPI) -> None:
    with TestClient(probe_app) as client:
        response = client.get("/crash", headers={"X-Request-ID": "crash-test"})
        assert response.status_code == 500
        assert response.json() == {
            "code": "internal_error",
            "message": "Internal server error",
            "request_id": "crash-test",
        }
        assert response.headers["x-request-id"] == "crash-test"
        assert response.headers["x-content-type-options"] == "nosniff"


def test_metrics_labels_do_not_include_user_path_or_query(probe_app: FastAPI) -> None:
    with TestClient(probe_app) as client:
        client.get("/objects/private-object-id?token=private-query-token")
        client.get("/unknown-private-path")
        metrics = client.get("/metrics")
        assert metrics.status_code == 200
        assert 'route="/objects/{object_id}"' in metrics.text
        assert 'route="unmatched"' in metrics.text
        assert "private-" not in metrics.text
        assert REGISTRY.get_sample_value(
            "aegis_http_requests_total",
            {"method": "GET", "route": "/objects/{object_id}", "status": "200"},
        )


def test_log_formatter_drops_arbitrary_messages_and_exception_text() -> None:
    record = logging.LogRecord(
        "httpx", logging.ERROR, __file__, 1, "password=%s", ("private-password",), None
    )
    record.exc_text = "Authorization: Bearer private-token"
    record.body = "private-body"
    record.query = "private-query"
    record.event = "http_error"
    token = REQUEST_ID.set("log-test")
    try:
        formatted = SafeJSONFormatter().format(record)
    finally:
        REQUEST_ID.reset(token)
    assert "private-" not in formatted
    assert json.loads(formatted)["event"] == "http_error"
    assert json.loads(formatted)["request_id"] == "log-test"


@pytest.mark.parametrize(
    ("ping_status", "query_status", "expected"),
    [(200, 200, "ok"), (302, 200, "unavailable"), (200, 403, "unavailable")],
)
def test_clickhouse_probe_is_authenticated_and_does_not_follow_redirects(
    monkeypatch: pytest.MonkeyPatch, ping_status: int, query_status: int, expected: str
) -> None:
    calls: list[httpx.Request] = []
    options: dict[str, Any] = {}
    real_client = httpx.Client

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path == "/ping":
            return httpx.Response(ping_status, text="Ok.\n", headers={"Location": "http://evil"})
        return httpx.Response(query_status, text="1\n")

    def client_factory(**kwargs: Any) -> httpx.Client:
        options.update(kwargs)
        return real_client(**kwargs, transport=httpx.MockTransport(respond))

    monkeypatch.setattr(health.httpx, "Client", client_factory)
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        clickhouse_url="http://clickhouse:8123",
        clickhouse_user="runtime",
        clickhouse_password=SecretStr("private-password"),
    )
    request = Request({"type": "http", "app": app})
    assert health._clickhouse_status(request) == expected
    assert options["follow_redirects"] is False
    assert options["trust_env"] is False
    assert options["timeout"] == 2.0
    assert all(item.url.host == "clickhouse" for item in calls)
    assert all(item.headers["authorization"].startswith("Basic ") for item in calls)
    assert len(calls) == (1 if ping_status != 200 else 2)
