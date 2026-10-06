"""Verify only selected original sources and construct the bounded response."""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.errors import ApiError
from app.modules.attack_timeline.cursors import Position, TimelineCursor
from app.modules.attack_timeline.queries import PAGE_BYTES
from app.modules.attack_timeline.schemas import AttackTimeline, TimelineEvent
from app.modules.entities.indexing import verified_document
from app.modules.ingestion.models import RawEvent
from app.modules.normalization.models import NormalizedEvent


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _event(row: dict[str, Any]) -> TimelineEvent:
    normalized = dict(row["normalized"])
    raw = dict(row["raw"])
    normalized["event_id"] = UUID(normalized["event_id"])
    for key in ("timestamp", "processed_at"):
        normalized[key] = _time(normalized[key])
    for key in ("id", "source_id", "dataset_id", "run_id"):
        raw[key] = UUID(raw[key])
    raw["received_at"] = _time(raw["received_at"])
    snapshot = NormalizedEvent(**normalized)
    event = verified_document(snapshot, RawEvent(**raw))
    return TimelineEvent(
        event_id=event.event_id,
        event_sha256=snapshot.document_sha256,
        event_snapshot=event,
        alerts=row["alerts"],
    )


def project(
    data: dict[str, Any], codec: TimelineCursor, position: Position | None
) -> AttackTimeline:
    incident = data["incident"]
    if incident is None:
        raise ApiError(404, "incident_not_found", "Incident not found")
    if data["limit_exceeded"]:
        raise ApiError(409, "attack_timeline_limit_exceeded", "Attack timeline exceeds its bounds")
    if data["integrity_mismatch"]:
        raise ApiError(
            409, "attack_timeline_integrity_mismatch", "Attack timeline evidence is invalid"
        )
    if position is not None and position.fingerprint != data["fingerprint"]:
        raise ApiError(
            409, "attack_timeline_changed", "Incident evidence changed; refresh the timeline"
        )
    if data["page_bytes"] > PAGE_BYTES:
        raise ApiError(409, "attack_timeline_page_too_large", "Use a smaller attack timeline page")
    try:
        items = [_event(row) for row in data["items"]]
        cursor = None
        if data["has_more"] and items:
            last = items[-1]
            cursor = codec.next(
                data["fingerprint"], last.event_snapshot.timestamp, last.event_id, position
            )
        return AttackTimeline(
            incident_id=incident["id"],
            incident_version=incident["version"],
            mode=incident["mode"],
            dataset_id=incident["dataset_id"],
            run_id=incident["run_id"],
            view_fingerprint=data["fingerprint"],
            total=data["total"],
            index_status=data["index_status"],
            items=items,
            next_cursor=cursor,
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ApiError(
            409, "attack_timeline_integrity_mismatch", "Attack timeline evidence is invalid"
        ) from None
