"""Reject unbounded/unexpected request bodies before application parsing."""

import asyncio
import json
from dataclasses import dataclass, field

import pytest
from fastapi.testclient import TestClient
from starlette.types import Message, Scope

from app.api.auth import LoginInput
from app.core.http import BodyLimitMiddleware
from app.main import create_app


@dataclass
class Exchange:
    consumed: int = 0
    delivered: bytes | None = None
    sent: list[Message] = field(default_factory=list)


def exchange(
    messages: list[Message],
    *,
    method: str = "POST",
    headers: list[tuple[bytes, bytes]] | None = None,
    path: str = "/unit-body",
) -> Exchange:
    """Feed actual ASGI chunks; the downstream parser must never see a rejected body."""
    result = Exchange()
    scope: Scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers if headers is not None else [(b"content-type", b"application/json")],
        "state": {"request_id": "bounded-body-test"},
    }

    async def receive() -> Message:
        message = messages[result.consumed]
        result.consumed += 1
        return message

    async def downstream(scope, receive, send) -> None:
        message = await receive()
        result.delivered = message.get("body", b"")
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"accepted"})

    async def send(message: Message) -> None:
        result.sent.append(message)

    asyncio.run(BodyLimitMiddleware(downstream)(scope, receive, send))
    return result


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
def test_body_limit_accepts_exactly_64_kib_and_rejects_next_byte(method: str) -> None:
    boundary = b"x" * 65536
    accepted = exchange([{"type": "http.request", "body": boundary}], method=method)
    assert accepted.delivered == boundary and accepted.sent[0]["status"] == 200
    rejected = exchange([{"type": "http.request", "body": boundary + b"x"}], method=method)
    assert rejected.delivered is None and rejected.sent[0]["status"] == 413
    assert json.loads(rejected.sent[1]["body"]) == {
        "code": "body_too_large",
        "message": "Request body rejected",
        "request_id": "bounded-body-test",
    }


@pytest.mark.parametrize("declared_length", [None, b"1", b"65536", b"999999999"])
def test_chunked_body_cannot_bypass_limit_with_missing_or_false_content_length(
    declared_length: bytes | None,
) -> None:
    headers = [(b"content-type", b"application/json"), (b"transfer-encoding", b"chunked")]
    if declared_length is not None:
        headers.append((b"content-length", declared_length))
    result = exchange(
        [
            {"type": "http.request", "body": b"x" * 32768, "more_body": True},
            {"type": "http.request", "body": b"y" * 32768, "more_body": True},
            {"type": "http.request", "body": b"private-body-secret", "more_body": True},
            {"type": "http.request", "body": b"unread-trailing-body"},
        ],
        headers=headers,
    )
    assert result.delivered is None and result.sent[0]["status"] == 413
    assert result.consumed == 3
    assert b"private-body-secret" not in result.sent[1]["body"]


def test_allowed_chunks_are_reassembled_without_losing_bytes() -> None:
    result = exchange(
        [
            {"type": "http.request", "body": b'{"username":', "more_body": True},
            {"type": "http.request", "body": b"", "more_body": True},
            {"type": "http.request", "body": b'"analyst"}'},
        ],
        headers=[(b"content-type", b"Application/JSON; charset=utf-8")],
    )
    assert result.sent[0]["status"] == 200
    assert result.delivered == b'{"username":"analyst"}'
    assert result.consumed == 3


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-type", b"text/plain")],
        [(b"content-type", b"application/x-www-form-urlencoded")],
        [(b"content-type", b"multipart/form-data; boundary=private-boundary")],
        [(b"content-type", b"application/json"), (b"content-encoding", b"gzip")],
        [(b"content-type", b"application/json"), (b"content-encoding", b"identity")],
    ],
)
def test_unsupported_content_is_rejected_without_reading_body(
    headers: list[tuple[bytes, bytes]],
) -> None:
    result = exchange([], headers=headers)
    assert result.sent[0]["status"] == 415
    assert result.consumed == 0 and result.delivered is None
    assert json.loads(result.sent[1]["body"])["code"] == "json_required"


def test_bodyless_post_without_content_type_is_allowed() -> None:
    result = exchange([{"type": "http.request", "body": b""}], headers=[])
    assert result.delivered == b"" and result.sent[0]["status"] == 200


def test_nonempty_chunk_without_content_type_is_rejected() -> None:
    result = exchange(
        [
            {"type": "http.request", "body": b"", "more_body": True},
            {"type": "http.request", "body": b"private-body-secret"},
        ],
        headers=[],
    )
    assert result.delivered is None and result.sent[0]["status"] == 415
    assert result.consumed == 2
    assert b"private-body-secret" not in result.sent[1]["body"]


def test_disconnected_upload_never_reaches_parser_or_sends_response() -> None:
    result = exchange(
        [
            {"type": "http.request", "body": b'{"incomplete":', "more_body": True},
            {"type": "http.disconnect"},
        ]
    )
    assert result.delivered is None and result.sent == []


def test_ingest_has_one_mib_limit_while_other_routes_keep_64_kib() -> None:
    body = b'{"raw_event":"' + b"x" * (1048576 - len(b'{"raw_event":""}')) + b'"}'
    assert len(body) == 1048576
    accepted = exchange([{"type": "http.request", "body": body}], path="/api/v1/events")
    assert accepted.sent[0]["status"] == 200 and accepted.delivered == body
    rejected = exchange([{"type": "http.request", "body": body + b" "}], path="/api/v1/events")
    assert rejected.sent[0]["status"] == 413 and rejected.delivered is None
    other = exchange([{"type": "http.request", "body": body}], path="/api/v1/sources")
    assert other.sent[0]["status"] == 413


@pytest.mark.parametrize(
    "body",
    [
        b'{"source_type":"generic_json","source_type":"nginx"}',
        b'{"raw_event":{"action":"a","action":"b"}}',
        b'{"raw_event":{"value":NaN}}',
        b'{"raw_event":{"value":Infinity}}',
        b'{"raw_event":{"value":-Infinity}}',
        b'{"raw_event":{"value":1e9999}}',
        b"[" * 2000 + b"0" + b"]" * 2000,
        b'{"raw_event":"private-malformed',
        b'{"raw_event":"\xff"}',
    ],
)
def test_ingest_rejects_ambiguous_nonfinite_deep_or_malformed_json(body: bytes) -> None:
    result = exchange([{"type": "http.request", "body": body}], path="/api/v1/events")
    assert result.sent[0]["status"] == 422 and result.delivered is None
    assert json.loads(result.sent[1]["body"])["code"] == "validation_error"
    assert b"private" not in result.sent[1]["body"]


def test_json_nesting_check_ignores_brackets_and_escapes_inside_strings() -> None:
    body = json.dumps({"raw_event": '[{"\\' * 100 + '"}'}).encode()
    result = exchange([{"type": "http.request", "body": body}], path="/api/v1/events")
    assert result.sent[0]["status"] == 200 and result.delivered == body


@pytest.mark.parametrize(
    "body",
    [
        b'{"username":"analyst","password":"short-secret"}',
        b'{"username":"analyst","password":"long-private-password","secret":"private-value"}',
        b'{"username":"analyst","password":"private-malformed',
    ],
)
def test_real_validation_error_handler_does_not_echo_payload(body: bytes) -> None:
    application = create_app()

    @application.post("/unit-validation")
    def validated(data: LoginInput) -> dict[str, str]:
        return {"username": data.username}

    # No context manager: no lifespan or infrastructure connection is required for this route.
    client = TestClient(application, client=("unit-http", 50000))
    try:
        response = client.post(
            "/unit-validation",
            content=body,
            headers={"Content-Type": "application/json", "X-Request-ID": "validation-test"},
        )
    finally:
        client.close()
    assert response.status_code == 422
    assert response.json() == {
        "code": "validation_error",
        "message": "Request fields are invalid",
        "request_id": "validation-test",
    }
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "secret" not in response.text and "private" not in response.text
