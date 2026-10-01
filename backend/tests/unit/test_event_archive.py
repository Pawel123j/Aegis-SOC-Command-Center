"""Archive transport redacts server errors and enforces response/resource bounds."""

import os
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.core.config import Settings
from app.modules.events.clickhouse import (
    ClickHouseEvents,
    ClickHouseUnavailable,
    escaped_parameter,
    execute,
    identifier,
    json_rows,
)


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    for name in list(os.environ):
        if name.startswith("AEGIS_"):
            monkeypatch.delenv(name)
    return Settings(
        database_url="postgresql+psycopg://aegis_app:unit-test-key@localhost/aegis",
        redis_url="redis://:unit-test-key@localhost/0",
        clickhouse_url="http://localhost:8123",
        clickhouse_user="aegis",
        clickhouse_password="unit-archive-key",
        jwt_secret="test-only-jwt-signing-material-with-32-bytes",
        public_origin="https://aegis.test",
    )


@pytest.mark.parametrize("status", [301, 302, 400, 401, 403, 500, 503])
def test_server_failure_and_redirects_are_redacted(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    client_type = httpx.Client
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.url.params["max_execution_time"] == "3"
        assert request.url.params["max_result_rows"] == "501"
        assert request.headers["authorization"].startswith("Basic ")
        return httpx.Response(
            status,
            text="secret-raw-payload-and-password",
            headers={"Location": "https://elsewhere.test"},
        )

    def client(**kwargs: Any) -> httpx.Client:
        return client_type(**kwargs, transport=httpx.MockTransport(handle))

    monkeypatch.setattr("app.modules.events.clickhouse.httpx.Client", client)
    with pytest.raises(ClickHouseUnavailable, match="^archive_unavailable$") as error:
        execute(settings, "SELECT 1", database="aegis")
    assert "secret" not in str(error.value) and len(seen) == 1


def test_response_body_is_bounded(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    client_type = httpx.Client
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * 33))
    monkeypatch.setattr("app.modules.events.clickhouse.MAX_RESPONSE_BYTES", 32)
    monkeypatch.setattr(
        "app.modules.events.clickhouse.httpx.Client",
        lambda **kwargs: client_type(**kwargs, transport=transport),
    )
    with pytest.raises(ClickHouseUnavailable, match="^archive_unavailable$"):
        execute(settings, "SELECT 1")


def test_network_failure_is_redacted(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    client_type = httpx.Client

    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("secret-credential-url", request=request)

    monkeypatch.setattr(
        "app.modules.events.clickhouse.httpx.Client",
        lambda **kwargs: client_type(**kwargs, transport=httpx.MockTransport(handle)),
    )
    with pytest.raises(ClickHouseUnavailable, match="^archive_unavailable$") as error:
        execute(settings, "SELECT 1")
    assert error.value.__cause__ is None


def test_owner_credentials_required_before_io(settings: Settings) -> None:
    with pytest.raises(ValueError, match="migration credentials"):
        execute(settings, "CREATE DATABASE aegis", owner=True)


@pytest.mark.parametrize("name", ["aegis;drop", "../aegis", "aegis.foo", "AEGIS", "", "a" * 65])
def test_untrusted_database_identifiers_are_rejected(name: str) -> None:
    with pytest.raises(ValueError):
        identifier(name)


@pytest.mark.parametrize("value", ["invalid", "[]", '"text"', "1", '{"x":1}\nraw-error'])
def test_malformed_server_rows_are_redacted(value: str) -> None:
    with pytest.raises(ClickHouseUnavailable, match="^archive_unavailable$"):
        json_rows(value)


def test_http_parameter_escaping() -> None:
    assert escaped_parameter(r"\N") == r"\\N"
    assert escaped_parameter("a\tb\nc\rd") == r"a\tb\nc\rd"


def test_pagination_uses_same_portable_uuid_order_in_cursor_and_sort(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.modules.events.schemas import SearchRequest

    statements: list[str] = []
    identifier_value = uuid4()
    start = datetime(2026, 10, 1, tzinfo=UTC)

    def command(configuration: Settings, sql: str, **kwargs: Any) -> str:
        statements.append(sql)
        if "count()" in sql:
            return '{"total":"0"}'
        assert kwargs["parameters"]["param_after_id"] == str(identifier_value)
        return ""

    monkeypatch.setattr("app.modules.events.clickhouse.execute", command)
    result = ClickHouseEvents(settings).search(
        SearchRequest(), start, start + timedelta(days=1), (start, identifier_value)
    )
    assert result == ([], 0)
    assert "(timestamp, toString(event_id)) <" in statements[-1]
    assert "{after_id:String}" in statements[-1]
    assert "ORDER BY timestamp DESC, toString(event_id) DESC" in statements[-1]
