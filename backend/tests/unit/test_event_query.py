"""The query grammar rejects executable syntax and bounds work before SQL compilation."""

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.modules.events.query import Boolean, Comparison, QueryError, compile_query, parse_query
from app.modules.events.schemas import SearchParams, SearchRequest
from app.modules.events.service import CursorCodec, CursorError


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


def test_aliases_typed_parameters_and_precedence() -> None:
    expression = parse_query('username = "żółć" OR result = "failed" AND source_port >= 22')
    assert isinstance(expression, Boolean) and expression.operator == "OR"
    assert isinstance(expression.right, Boolean) and expression.right.operator == "AND"
    sql, parameters = compile_query(expression)
    assert "żółć" not in sql and "failure" not in sql
    assert (
        sql == "(user_name = {q0:String} OR "
        "(event_outcome = {q1:String} AND source_port >= {q2:UInt32}))"
    )
    assert parameters == {"param_q0": "żółć", "param_q1": "failure", "param_q2": "22"}


def test_parentheses_ip_uuid_null_and_contains() -> None:
    assert parse_query('source.ip = "2001:db8::01"') == Comparison("source.ip", "=", "2001:db8::1")
    identifier = uuid4()
    assert parse_query(f'event_id = "{identifier}"') == Comparison("event_id", "=", str(identifier))
    assert compile_query(parse_query("user.name = null")) == ("isNull(user_name)", {})
    assert compile_query(parse_query("host.name != null")) == ("isNotNull(host_name)", {})
    assert (
        "positionUTF8(command_line, {q0:String})"
        in compile_query(parse_query('command_line CONTAINS "powershell"'))[0]
    )
    assert isinstance(
        parse_query('(username = "a" OR hostname = "b") AND action = "login"'), Boolean
    )


@pytest.mark.parametrize(
    "value",
    [
        'username = "a"; DROP TABLE events',
        'username = "a" -- comment',
        'username = "a" /* comment */',
        "user.name = now()",
        'user.name IN ("a")',
        'document = "x"',
        'alert.severity = "high"',
        'source.ip = "not an IP"',
        "source.port = 65536",
        "source.port = -1",
        'source.port = "22"',
        "source.port = 1.5",
        'severity = "urgent"',
        'result = "whatever"',
        'event_id = "broken"',
        'mode = "admin"',
        "username = true",
        'username = "a" UNION SELECT 1',
        'username = "a" AND',
        'username = "a" OR OR username = "b"',
        '(username = "a"',
        'username = "a")',
        'username > "a"',
        'source.ip CONTAINS "192.0.2.1"',
        "source.port CONTAINS 10",
        'user.name = "\\ud800"',
        'user.name = "\\u0000"',
        'user.name = "\\x41"',
        "username > null",
        "=" * 4100,
        "(" * 14 + 'username = "a"' + ")" * 14,
        " OR ".join(['username = "a"'] * 65),
    ],
)
def test_query_rejects_unsupported_or_malformed_input(value: str) -> None:
    with pytest.raises(QueryError):
        parse_query(value)


def test_sql_payload_inside_quoted_literal_remains_parameter_only() -> None:
    value = '"; DROP TABLE events; --'
    import json

    sql, parameters = compile_query(parse_query("username = " + json.dumps(value)))
    assert sql == "user_name = {q0:String}"
    assert parameters == {"param_q0": value}


@pytest.mark.parametrize(
    "values",
    [
        {"from": "2026-10-01T00:00:00"},
        {"from": 1790812800},
        {"from": "1790812800"},
        {"from": "1969-12-31T23:59:59Z", "to": "1970-01-01T00:00:01Z"},
        {"from": "2299-12-31T23:59:59Z", "to": "2300-01-01T00:00:01Z"},
        {"limit": 0},
        {"limit": 501},
        {"limit": True},
        {"limit": "100"},
        {"mode": "unknown"},
        {"q": 'raw_event = "x"'},
        {"from": "2026-10-01T00:00:00Z", "to": "2026-10-09T00:00:00Z"},
        {"from": "2026-10-01T00:00:00Z", "to": "2026-10-01T00:00:00Z"},
        {"extra": "unknown"},
        {"cursor": ""},
    ],
)
def test_search_bounds(values: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SearchRequest.model_validate(values)


def test_get_parameters_parse_bounded_integer_strings() -> None:
    assert SearchParams.model_validate({"limit": "500"}).limit == 500
    with pytest.raises(ValidationError):
        SearchParams.model_validate({"limit": "501"})


def test_cursor_binds_window_principal_database_query_scope_and_limit(settings: Settings) -> None:
    start = datetime(2026, 10, 1, tzinfo=UTC)
    end = start + timedelta(hours=24)
    request = SearchRequest(q='username = "żółć"', limit=5, source_id=uuid4())
    user = uuid4()
    after = start + timedelta(hours=4), uuid4()
    codec = CursorCodec(settings)
    cursor = codec.issue(request, user, "aegis", start, end, after)
    continuation = request.model_copy(update={"cursor": cursor})
    assert codec.read(continuation, user, "aegis") == (start, end, after)
    for altered, principal, database in [
        (continuation, uuid4(), "aegis"),
        (continuation, user, "aegis_other"),
        (continuation.model_copy(update={"q": ""}), user, "aegis"),
        (continuation.model_copy(update={"limit": 10}), user, "aegis"),
        (continuation.model_copy(update={"source_id": uuid4()}), user, "aegis"),
        (continuation.model_copy(update={"from_": start + timedelta(seconds=1)}), user, "aegis"),
        (continuation.model_copy(update={"cursor": cursor + "x"}), user, "aegis"),
    ]:
        with pytest.raises(CursorError):
            codec.read(altered, principal, database)


def test_expired_and_invalid_cursors(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    codec = CursorCodec(settings)
    request = SearchRequest()
    user = uuid4()
    start = datetime(2026, 10, 1, tzinfo=UTC)
    monkeypatch.setattr("app.modules.events.service.time.time", lambda: 10000)
    cursor = codec.issue(request, user, "aegis", start, start + timedelta(days=1), (start, uuid4()))
    monkeypatch.setattr("app.modules.events.service.time.time", lambda: 10901)
    for value in [cursor, "invalid", "x.x", "!..!", "", "a.b.c"]:
        with pytest.raises(CursorError):
            codec.read(request.model_copy(update={"cursor": value}), user, "aegis")
