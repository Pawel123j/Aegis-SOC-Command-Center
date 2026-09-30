"""Admission rejects invalid envelopes before writing any durable event."""

import json
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.modules.ingestion.processing import EventSnapshot, validate_raw_event
from app.modules.ingestion.schemas import (
    MAX_JSON_DEPTH,
    MAX_RAW_BYTES,
    RawEnvelope,
    SourceType,
    batch_hash,
    canonical_envelope,
    canonical_json,
    envelope_hash,
    parse_envelopes,
)


def envelope(raw_event: Any = None, **fields: Any) -> dict[str, Any]:
    return {"source_type": "generic_json", "raw_event": raw_event, **fields}


@pytest.mark.parametrize("source_type", list(SourceType))
def test_known_source_types(source_type: SourceType) -> None:
    result = RawEnvelope.model_validate({"source_type": source_type, "raw_event": {"value": 1}})
    assert result.source_type == source_type


@pytest.mark.parametrize(
    "raw_event", ["", "  ", "not yet parsed", {"nested": [1, True, None, "x"]}]
)
def test_content_validation_is_deferred_but_envelope_is_valid(raw_event: Any) -> None:
    assert RawEnvelope.model_validate(envelope(raw_event)).raw_event == raw_event


@pytest.mark.parametrize("raw_event", [None, [], 1, True, b"bytes", (1,), {1: "wrong key"}])
def test_invalid_raw_types_are_rejected(raw_event: Any) -> None:
    with pytest.raises(ValidationError):
        RawEnvelope.model_validate(envelope(raw_event))


@pytest.mark.parametrize(
    "raw_event",
    [{"n": math.nan}, {"n": math.inf}, {"n": -math.inf}, {"time": datetime.now(UTC)}],
)
def test_raw_json_must_be_finite_json(raw_event: Any) -> None:
    with pytest.raises(ValidationError):
        RawEnvelope.model_validate(envelope(raw_event))


@pytest.mark.parametrize(
    "raw_event", ["\x00", {"k": "\x00"}, {"\x00": "v"}, "\ud800", {"\udfff": 1}]
)
def test_postgresql_incompatible_unicode_is_rejected(raw_event: Any) -> None:
    with pytest.raises(ValidationError):
        RawEnvelope.model_validate(envelope(raw_event))


def test_raw_string_limit_counts_utf8_bytes() -> None:
    assert RawEnvelope.model_validate(envelope("ą" * (MAX_RAW_BYTES // 2)))
    with pytest.raises(ValidationError):
        RawEnvelope.model_validate(envelope("ą" * (MAX_RAW_BYTES // 2 + 1)))


def test_object_limit_includes_json_structure() -> None:
    value = {"x": "a" * (MAX_RAW_BYTES - len(canonical_json({"x": ""})))}
    assert len(canonical_json(value)) == MAX_RAW_BYTES
    assert RawEnvelope.model_validate(envelope(value))
    value["x"] += "a"
    with pytest.raises(ValidationError):
        RawEnvelope.model_validate(envelope(value))


def test_raw_object_depth_is_bounded() -> None:
    value: dict[str, Any] = {"leaf": True}
    for _ in range(MAX_JSON_DEPTH - 1):
        value = {"nested": value}
    assert RawEnvelope.model_validate(envelope(value))
    with pytest.raises(ValidationError):
        RawEnvelope.model_validate(envelope({"nested": value}))


@pytest.mark.parametrize(
    "extra",
    [
        {"unknown": 1},
        {"source_type": "unsupported"},
        {"source_event_id": ""},
        {"source_event_id": "x" * 129},
        {"source_event_id": 42},
        {"source_event_id": "\x00"},
        {"timestamp": "2026-09-28T12:00:00"},
        {"timestamp": 1780000000},
        {"timestamp": "1700000000"},
        {"timestamp": "2026-09-28"},
        {"timestamp": "2026-09-28 12:00:00Z"},
        {"timestamp": "2026-09-28T12:00:00+0200"},
        {"timezone": "Mars/Olympus"},
        {"timezone": "../Europe/Warsaw"},
    ],
)
def test_invalid_metadata_is_rejected(extra: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        RawEnvelope.model_validate(envelope({}, **extra))


def test_timestamps_normalize_to_utc_and_optional_nulls_are_canonical() -> None:
    first = RawEnvelope.model_validate(envelope({}, timestamp="2026-09-28T14:00:00+02:00"))
    second = RawEnvelope.model_validate(
        envelope({}, timestamp="2026-09-28T12:00:00Z", timezone=None)
    )
    assert canonical_envelope(first)["timestamp"] == "2026-09-28T12:00:00Z"
    assert envelope_hash(first) == envelope_hash(second)


def test_internal_aware_datetime_is_accepted() -> None:
    value = datetime(2026, 9, 28, 12, tzinfo=UTC)
    assert RawEnvelope.model_validate(envelope({}, timestamp=value)).timestamp == value


def test_internal_naive_datetime_is_rejected() -> None:
    with pytest.raises(ValidationError):
        RawEnvelope.model_validate(envelope({}, timestamp=datetime(2026, 9, 28, 12)))


def test_iana_timezone_is_preserved() -> None:
    result = RawEnvelope.model_validate(envelope({}, timezone="Europe/Warsaw"))
    assert result.timezone == "Europe/Warsaw"


def test_canonical_hash_ignores_object_order_but_preserves_event_order() -> None:
    first = RawEnvelope.model_validate(envelope({"z": 1, "a": "ą"}))
    equivalent = RawEnvelope.model_validate(envelope({"a": "ą", "z": 1}))
    second = RawEnvelope.model_validate(envelope({"different": True}))
    assert envelope_hash(first) == envelope_hash(equivalent)
    assert batch_hash([first, second]) != batch_hash([second, first])


@pytest.mark.parametrize("value", [1.0, -0.0, 1e20, 1e100, 1e-7, -1e20])
def test_canonical_numbers_survive_postgresql_jsonb_number_normalization(value: float) -> None:
    restored: int | float = int(value) if value.is_integer() else value
    assert canonical_json({"nested": [value]}) == canonical_json({"nested": [restored]})
    stored = canonical_envelope(RawEnvelope.model_validate(envelope({"value": value})))
    assert stored["raw_event"]["value"] == restored
    if value.is_integer():
        assert type(stored["raw_event"]["value"]) is int


def test_single_and_batch_wrapper_have_same_body_hash() -> None:
    body = envelope({"message": "test"})
    assert batch_hash(parse_envelopes(body)) == batch_hash(parse_envelopes({"events": [body]}))


@pytest.mark.parametrize("body", [[], {"events": []}, {"events": [envelope({})], "extra": 1}])
def test_unsupported_batch_shapes_are_rejected(body: Any) -> None:
    with pytest.raises(ValidationError):
        parse_envelopes(body)


def test_batch_bound_and_whole_batch_validation() -> None:
    assert len(parse_envelopes({"events": [envelope({})] * 500})) == 500
    with pytest.raises(ValidationError):
        parse_envelopes({"events": [envelope({})] * 501})
    with pytest.raises(ValidationError):
        parse_envelopes({"events": [envelope({}), envelope([])]})


def test_synthetic_format_fixtures_pass_intake_and_raw_staging_validation() -> None:
    path = Path(__file__).parents[1] / "fixtures" / "ingestion-samples.json"
    records = parse_envelopes(json.loads(path.read_text(encoding="utf-8")))
    assert len(records) == 7
    assert {record.source_type for record in records} == set(SourceType)
    assert len({record.source_event_id for record in records}) == len(records)
    for index, record in enumerate(records, start=1):
        assert record.timestamp is not None and record.timestamp.tzinfo == UTC
        body = canonical_envelope(record)
        encoded = canonical_json(body)
        snapshot = EventSnapshot(
            event_id=UUID(int=index),
            envelope=body,
            payload_hash=envelope_hash(record),
            payload_bytes=len(encoded),
            source_type=record.source_type.value,
        )
        validate_raw_event(snapshot)
        # This phase preserves raw contents; parsing and normalization are separate.
        assert canonical_json(snapshot.envelope) == encoded
