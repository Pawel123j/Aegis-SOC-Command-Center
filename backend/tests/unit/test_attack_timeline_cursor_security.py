"""Independent signed-cursor trust boundaries and nonrenewing observation pagination."""

import base64
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from app.core.errors import ApiError
from app.modules.attack_timeline.cursors import NAMESPACE, TTL_SECONDS, TimelineCursor
from app.modules.ingestion.schemas import canonical_json

SECRET = "independent-timeline-test-secret"
NOW = 1_800_000_000
FINGERPRINT = "ab" * 32
FUTURE = datetime(2099, 1, 1, 8, 0, 0, 123456, tzinfo=UTC)
SCOPE = {
    "user_id": str(UUID(int=1)),
    "path": f"/api/v1/incidents/{UUID(int=2)}/attack-timeline",
    "limit": 1,
}


@pytest.fixture(autouse=True)
def frozen_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.modules.attack_timeline.cursors.time.time", lambda: NOW)


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def signed(data: dict[str, Any], namespace: str = NAMESPACE) -> str:
    payload = canonical_json(data)
    key = hmac.digest(SECRET.encode(), namespace.encode(), "sha256")
    return encode(payload) + "." + encode(hmac.digest(key, payload, "sha256"))


def body() -> dict[str, Any]:
    token = TimelineCursor(SECRET, SCOPE).next(FINGERPRINT, FUTURE, UUID(int=3))
    encoded = token.split(".")[0]
    return dict(json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))))


def rejects(token: str, codec: TimelineCursor | None = None) -> None:
    with pytest.raises(ApiError) as rejected:
        (codec or TimelineCursor(SECRET, SCOPE)).read(token)
    assert rejected.value.status == 422 and rejected.value.code == "invalid_cursor"


def test_future_time_preserves_microseconds_independently_of_cursor_clock() -> None:
    codec = TimelineCursor(SECRET, SCOPE)
    value = codec.read(codec.next(FINGERPRINT, FUTURE, UUID(int=3)))
    assert value is not None
    assert value.moment == FUTURE and value.moment.microsecond == 123456
    assert value.fingerprint == FINGERPRINT and value.event_id == UUID(int=3)
    assert value.issued == NOW and value.expires == NOW + TTL_SECONDS


def test_pagination_cannot_extend_original_fifteen_minute_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codec = TimelineCursor(SECRET, SCOPE)
    original = codec.read(codec.next(FINGERPRINT, FUTURE, UUID(int=3)))
    assert original is not None
    monkeypatch.setattr("app.modules.attack_timeline.cursors.time.time", lambda: NOW + 899)
    next_token = codec.next(FINGERPRINT, FUTURE + timedelta(microseconds=1), UUID(int=4), original)
    continued = codec.read(next_token)
    assert continued is not None and continued.issued == original.issued
    assert continued.expires == original.expires
    monkeypatch.setattr("app.modules.attack_timeline.cursors.time.time", lambda: NOW + 900)
    rejects(next_token)


@pytest.mark.parametrize(
    "field,value",
    [
        ("user_id", str(UUID(int=4))),
        ("path", f"/api/v1/incidents/{UUID(int=5)}/attack-timeline"),
        ("limit", 2),
    ],
)
def test_scope_binds_principal_incident_resource_and_page_size(field: str, value: Any) -> None:
    token = TimelineCursor(SECRET, SCOPE).next(FINGERPRINT, FUTURE, UUID(int=3))
    rejects(token, TimelineCursor(SECRET, {**SCOPE, field: value}))


def test_namespace_separates_other_application_cursors() -> None:
    rejects(signed(body(), namespace="aegis-incident-cursor-v1"))


@pytest.mark.parametrize(
    "field,value",
    [
        ("v", True),
        ("v", "1"),
        ("v", 2),
        ("scope", "0" * 64),
        ("fingerprint", "ab" * 31),
        ("fingerprint", "AB" * 32),
        ("fingerprint", None),
        ("time", "not-a-date"),
        ("time", "2099-01-01T08:00:00.123456"),
        ("time", "2099-01-01T09:00:00.123456+01:00"),
        ("time", None),
        ("id", "../other-event"),
        ("id", False),
        ("issued", True),
        ("issued", NOW + 1),
        ("expires", True),
        ("expires", NOW + TTL_SECONDS + 1),
    ],
)
def test_even_correctly_signed_tokens_reject_invalid_types_scope_and_coordinates(
    field: str, value: Any
) -> None:
    rejects(signed({**body(), field: value}))


@pytest.mark.parametrize("change", ["missing", "extra", "expired"])
def test_signed_schema_is_exact_and_expired_cursor_never_returns_position(change: str) -> None:
    data = body()
    if change == "missing":
        data.pop("fingerprint")
    elif change == "extra":
        data["alert_id"] = str(UUID(int=6))
    else:
        data["issued"] = NOW - TTL_SECONDS
        data["expires"] = NOW
    rejects(signed(data))


@pytest.mark.parametrize("part", [0, 1])
def test_payload_and_signature_tampering_are_rejected(part: int) -> None:
    pieces = signed(body()).split(".")
    pieces[part] = ("A" if pieces[part][0] != "A" else "B") + pieces[part][1:]
    rejects(".".join(pieces))


@pytest.mark.parametrize("token", ["", "%%%", "a.b.c", "x" * 4097])
def test_malformed_and_oversized_wire_tokens_have_sanitized_errors(token: str) -> None:
    rejects(token)


def test_position_fingerprint_is_preserved_for_service_freshness_comparison() -> None:
    changed = "cd" * 32
    value = TimelineCursor(SECRET, SCOPE).read(signed({**body(), "fingerprint": changed}))
    assert value is not None and value.fingerprint == changed
