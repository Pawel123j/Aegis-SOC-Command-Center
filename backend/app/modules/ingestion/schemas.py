"""Strict envelopes and the single canonical representation used for deduplication."""

import hashlib
import json
import math
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

MAX_RAW_BYTES = 65536
MAX_JSON_DEPTH = 16
RFC3339_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z"
)


class SourceType(StrEnum):
    GENERIC_JSON = "generic_json"
    LINUX_AUTH = "linux_auth"
    WINDOWS_AUTH = "windows_auth"
    WINDOWS_PROCESS = "windows_process"
    FIREWALL = "firewall"
    NGINX = "nginx"


def canonical_json(value: object) -> bytes:
    """Stable JSON bytes; invalid Unicode and non-finite numbers are never stored."""
    try:
        return json.dumps(
            _canonical_numbers(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise ValueError("a UTF-8 JSON value is required") from error


def _canonical_numbers(value: object) -> object:
    # JSONB may return an integral JSON float such as 1e20 as a Python int.
    # Normalize before hashing so durable round trips preserve content hashes.
    if isinstance(value, float) and math.isfinite(value) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {key: _canonical_numbers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_canonical_numbers(item) for item in value]
    return value


def validate_timezone(value: str) -> str:
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise ValueError("an IANA timezone is required") from error
    return value


def _validate_json_tree(value: object) -> None:
    # Iterative validation bounds depth before recursive JSON serialization.
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if type(current) in (dict, list):
            if depth > MAX_JSON_DEPTH:
                raise ValueError("raw JSON exceeds the nesting limit")
            if isinstance(current, dict):
                if any(type(key) is not str for key in current):
                    raise ValueError("JSON object keys must be strings")
                if any("\x00" in key for key in current):
                    raise ValueError("JSON object keys cannot contain NUL")
                children: Iterable[object] = current.values()
            else:
                assert isinstance(current, list)
                children = current
            stack.extend((child, depth + 1) for child in children)
        elif type(current) is float:
            if not math.isfinite(current):
                raise ValueError("JSON numbers must be finite")
        elif isinstance(current, str) and "\x00" in current:
            raise ValueError("raw_event cannot contain NUL")
        elif type(current) not in (str, int, bool, type(None)):
            raise ValueError("raw_event must contain only JSON values")


class RawEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    source_type: SourceType
    raw_event: str | dict[str, Any]
    source_event_id: str | None = Field(default=None, min_length=1, max_length=128, strict=True)
    timestamp: AwareDatetime | None = None
    timezone: str | None = Field(default=None, min_length=1, max_length=64, strict=True)

    @field_validator("raw_event", mode="before")
    @classmethod
    def validate_raw_event(cls, value: object) -> object:
        if type(value) not in (str, dict):
            raise ValueError("raw_event must be a string or JSON object")
        _validate_json_tree(value)
        try:
            size = (
                len(value.encode("utf-8")) if isinstance(value, str) else len(canonical_json(value))
            )
        except UnicodeError as error:
            raise ValueError("raw_event must be valid UTF-8") from error
        if size > MAX_RAW_BYTES:
            raise ValueError("raw_event exceeds 65536 UTF-8 bytes")
        return value

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_timestamp_type(cls, value: object) -> object:
        if value is not None and not isinstance(value, (str, datetime)):
            raise ValueError("timestamp must be an aware RFC 3339 datetime")
        if isinstance(value, str) and not RFC3339_TIMESTAMP.fullmatch(value):
            raise ValueError("timestamp must be an aware RFC 3339 datetime")
        return value

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime | None) -> datetime | None:
        return value.astimezone(UTC) if value is not None else None

    @field_validator("timezone")
    @classmethod
    def check_timezone(cls, value: str | None) -> str | None:
        return validate_timezone(value) if value is not None else None

    @field_validator("source_event_id")
    @classmethod
    def validate_event_id(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                value.encode("utf-8")
            except UnicodeError as error:
                raise ValueError("source_event_id must be valid UTF-8") from error
            if "\x00" in value:
                raise ValueError("source_event_id cannot contain NUL")
        return value


class EnvelopeBatch(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    events: list[RawEnvelope] = Field(min_length=1, max_length=500)


def parse_envelopes(body: object) -> list[RawEnvelope]:
    if isinstance(body, dict) and "events" in body:
        return EnvelopeBatch.model_validate(body).events
    return [RawEnvelope.model_validate(body)]


def canonical_envelope(envelope: RawEnvelope) -> dict[str, Any]:
    body = _canonical_numbers(envelope.model_dump(mode="json", exclude_none=True))
    assert isinstance(body, dict)
    return body


def canonical_envelope_bytes(envelope: dict[str, Any]) -> bytes:
    return canonical_json(envelope)


def envelope_hash(envelope: RawEnvelope) -> str:
    return hashlib.sha256(canonical_json(canonical_envelope(envelope))).hexdigest()


def batch_hash(envelopes: list[RawEnvelope]) -> str:
    return hashlib.sha256(
        canonical_json([canonical_envelope(item) for item in envelopes])
    ).hexdigest()
