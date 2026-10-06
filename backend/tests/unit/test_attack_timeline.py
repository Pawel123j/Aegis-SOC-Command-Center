"""Original source verification and timeline projection failures without storage."""

import hashlib
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from app.core.errors import ApiError
from app.modules.attack_timeline.cursors import Position, TimelineCursor
from app.modules.attack_timeline.queries import PAGE_BYTES
from app.modules.attack_timeline.views import project
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.parsers import NormalizationContext, normalize

NOW = datetime(2026, 10, 5, 12, tzinfo=UTC)
EVENT, SOURCE, DATASET, INCIDENT, ALERT = [UUID(int=value) for value in range(1, 6)]


def fixture() -> dict[str, Any]:
    envelope = {
        "source_type": "generic_json",
        "source_event_id": "original-1",
        "timestamp": NOW.isoformat(),
        "raw_event": {"message": "Observed source fact"},
    }
    encoded = canonical_json(envelope)
    raw_hash = hashlib.sha256(encoded).hexdigest()
    context = NormalizationContext(
        event_id=EVENT,
        source_id=SOURCE,
        dataset_id=DATASET,
        run_id=UUID(int=0),
        source_event_id="original-1",
        mode="live",
        source_name="Fixture source",
        source_type="generic_json",
        timezone="UTC",
        received_at=NOW + timedelta(seconds=1),
        processed_at=NOW + timedelta(seconds=2),
        raw_sha256=raw_hash,
    )
    event = normalize(envelope, context).model_dump(mode="json")
    normalized = {
        "event_id": str(EVENT),
        "timestamp": event["timestamp"],
        "processed_at": event["processed_at"],
        "schema_version": event["schema_version"],
        "parser_version": event["parser_version"],
        "document": event,
        "document_sha256": hashlib.sha256(canonical_json(event)).hexdigest(),
    }
    raw = {
        "id": str(EVENT),
        "source_id": str(SOURCE),
        "dataset_id": str(DATASET),
        "run_id": str(UUID(int=0)),
        "source_event_id": "original-1",
        "mode": "live",
        "source_type": "generic_json",
        "envelope": envelope,
        "payload_hash": raw_hash,
        "payload_bytes": len(encoded),
        "received_at": event["received_at"],
        "request_id": "fixture",
    }
    return {
        "incident": {
            "id": str(INCIDENT),
            "version": 1,
            "mode": "live",
            "dataset_id": None,
            "run_id": str(UUID(int=0)),
        },
        "limit_exceeded": False,
        "integrity_mismatch": False,
        "fingerprint": "a" * 64,
        "page_bytes": 1000,
        "total": 1,
        "has_more": False,
        "index_status": {
            "eligible_alerts": 1,
            "indexed_alerts": 1,
            "pending_alerts": 0,
            "complete": True,
        },
        "items": [
            {
                "normalized": normalized,
                "raw": raw,
                "alerts": [
                    {
                        "id": str(ALERT),
                        "title": "Observed alert",
                        "severity": "medium",
                        "status": "new",
                        "detection_type": "single_event",
                        "rule_id": "fixture",
                        "rule_version": "1.0.0",
                        "linked_at": NOW.isoformat(),
                    }
                ],
            }
        ],
    }


def codec() -> TimelineCursor:
    return TimelineCursor("test secret", {"user_id": "fixture", "path": "/fixture", "limit": 1})


def test_projection_verifies_original_snapshot_and_preserves_source() -> None:
    data = fixture()
    before = deepcopy(data)
    result = project(data, codec(), None)
    assert (
        result.items[0].event_snapshot.model_dump(mode="json")
        == before["items"][0]["normalized"]["document"]
    )
    assert result.items[0].event_id == EVENT and result.total == 1
    assert result.next_cursor is None and data == before


@pytest.mark.parametrize(
    "target,field,value",
    [
        ("normalized", "document_sha256", "b" * 64),
        ("normalized", "timestamp", "2026-10-05T11:00:00Z"),
        ("normalized", "parser_version", "altered"),
        ("raw", "payload_hash", "b" * 64),
        ("raw", "payload_bytes", 1),
        ("raw", "source_id", str(UUID(int=9))),
        ("raw", "dataset_id", str(UUID(int=9))),
        ("raw", "run_id", str(UUID(int=9))),
        ("raw", "received_at", "2026-10-05T11:00:00Z"),
        ("raw", "source_event_id", "altered"),
    ],
)
def test_selected_source_mismatch_fails_closed(target: str, field: str, value: Any) -> None:
    data = fixture()
    data["items"][0][target][field] = value
    with pytest.raises(ApiError) as error:
        project(data, codec(), None)
    assert error.value.status == 409 and error.value.code == "attack_timeline_integrity_mismatch"


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("incident", None, "incident_not_found"),
        ("limit_exceeded", True, "attack_timeline_limit_exceeded"),
        ("integrity_mismatch", True, "attack_timeline_integrity_mismatch"),
        ("page_bytes", PAGE_BYTES + 1, "attack_timeline_page_too_large"),
    ],
)
def test_query_guards_reject_before_source_verification(field: str, value: Any, code: str) -> None:
    data = fixture()
    data[field] = value
    data["items"] = [{"untrusted": "must not be inspected"}]
    with pytest.raises(ApiError) as error:
        project(data, codec(), None)
    assert error.value.code == code


def test_changed_view_requires_refresh_without_returning_old_cursor_page() -> None:
    position = Position("b" * 64, NOW, EVENT, 1, 901)
    with pytest.raises(ApiError) as error:
        project(fixture(), codec(), position)
    assert error.value.status == 409 and error.value.code == "attack_timeline_changed"


def test_next_page_key_comes_from_verified_observation_and_current_view() -> None:
    data = fixture()
    data["has_more"] = True
    result = project(data, codec(), None)
    position = codec().read(result.next_cursor)
    assert position is not None and position.moment == NOW and position.event_id == EVENT
    assert position.fingerprint == data["fingerprint"]
