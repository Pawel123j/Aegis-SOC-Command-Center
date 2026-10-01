"""Fence durable input admission before advancing the final event-time frontier."""

import hashlib
import hmac
from datetime import datetime, timedelta

from sqlalchemy import exists, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.infrastructure.database import ADMIN_LOCK_ID, Database
from app.modules.correlation.contracts import ALLOWED_LATENESS_SECONDS, MAX_FUTURE_SECONDS
from app.modules.correlation.engine import entity_keys
from app.modules.correlation.models import CorrelationJob, CorrelationScope
from app.modules.ingestion.models import IngestCapacity, OutboxJob, RawEvent
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.models import NormalizedEvent, PipelineJob
from app.modules.normalization.schemas import NormalizedSecurityEvent


def raw_namespace(raw: RawEvent) -> str:
    return "live" if raw.mode == "live" else f"replay:{raw.dataset_id}:{raw.run_id}"


def validated(snapshot: NormalizedEvent, raw: RawEvent) -> NormalizedSecurityEvent:
    if not hmac.compare_digest(
        hashlib.sha256(canonical_json(snapshot.document)).hexdigest(), snapshot.document_sha256
    ):
        raise ValueError("integrity_mismatch")
    event = NormalizedSecurityEvent.model_validate(snapshot.document)
    if (
        event.event_id != snapshot.event_id
        or event.event_id != raw.id
        or event.timestamp != snapshot.timestamp
        or event.received_at != raw.received_at
        or event.source_id != raw.source_id
        or event.dataset_id != raw.dataset_id
        or event.mode != raw.mode
        or event.run_id != raw.run_id
    ):
        raise ValueError("integrity_mismatch")
    return event


def missing_normalized() -> ColumnElement[bool]:
    return ~exists(
        select(CorrelationJob.event_id).where(CorrelationJob.event_id == NormalizedEvent.event_id)
    )


def ensure_scope(db: Session, scope: str) -> CorrelationScope:
    db.execute(insert(CorrelationScope).values(namespace=scope).on_conflict_do_nothing())
    row = db.get(CorrelationScope, scope)
    assert row is not None
    return row


def fenced_admission(database: Database, limit: int, now: datetime) -> dict[str, int]:
    counts = {"admitted": 0, "quarantined": 0, "late": 0, "clock_skew": 0}
    with database.sessions() as db:
        db.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": ADMIN_LOCK_ID})
        # Admission assigns received_at AFTER this same row lock. No old open input
        # transaction can cross the frontier, and no source lock is acquired here.
        db.scalar(select(IngestCapacity).where(IngestCapacity.id == 1).with_for_update())
        records = db.execute(
            select(NormalizedEvent, RawEvent)
            .join(RawEvent, RawEvent.id == NormalizedEvent.event_id)
            .where(missing_normalized())
            .order_by(NormalizedEvent.processed_at, NormalizedEvent.event_id)
            .limit(limit)
        ).all()
        for snapshot, raw in records:
            scope = ensure_scope(db, raw_namespace(raw))
            state, error = "pending", None
            keys: dict[str, str | None] = {
                name: None for name in ("same_user", "same_host", "same_ip", "same_process")
            }
            try:
                event = validated(snapshot, raw)
                keys = {
                    field: hashlib.sha256(value.encode()).hexdigest() if value else None
                    for field, value in entity_keys(event).items()
                }
                if event.mode == "live" and event.timestamp > event.received_at + timedelta(
                    seconds=MAX_FUTURE_SECONDS
                ):
                    state, error = "clock_skew", "timestamp_ahead_of_received_at"
                elif event.mode == "live" and event.timestamp < event.received_at - timedelta(
                    seconds=ALLOWED_LATENESS_SECONDS
                ):
                    state, error = "late", "outside_allowed_lateness"
                elif (
                    event.mode == "live"
                    and scope.watermark is not None
                    and event.timestamp <= scope.watermark
                ):
                    state, error = "late", "behind_final_watermark"
                elif event.mode == "replay" and scope.sealed_at is not None:
                    manifest = {
                        item["event_id"]: item["document_sha256"] for item in scope.manifest
                    }
                    if manifest.get(str(event.event_id)) != snapshot.document_sha256:
                        state, error = "late", "outside_sealed_manifest"
            except (KeyError, TypeError, ValueError):
                state, error = "quarantined", "integrity_mismatch"
            db.add(
                CorrelationJob(
                    event_id=snapshot.event_id,
                    namespace=scope.namespace,
                    timestamp=snapshot.timestamp,
                    state=state,
                    error_code=error,
                    processed_at=now if state != "pending" else None,
                    **keys,
                )
            )
            counts["admitted"] += 1
            if state != "pending":
                counts[state] += 1
        db.flush()
        undiscovered = db.scalar(
            select(exists(select(NormalizedEvent.event_id).where(missing_normalized())))
        )
        unknown_input = db.scalar(
            select(
                exists(
                    select(RawEvent.id).where(
                        ~exists(
                            select(NormalizedEvent.event_id).where(
                                NormalizedEvent.event_id == RawEvent.id
                            )
                        ),
                        ~exists(
                            select(OutboxJob.event_id).where(
                                OutboxJob.event_id == RawEvent.id, OutboxJob.state == "quarantined"
                            )
                        ),
                        ~exists(
                            select(PipelineJob.event_id).where(
                                PipelineJob.event_id == RawEvent.id,
                                PipelineJob.state == "quarantined",
                            )
                        ),
                    )
                )
            )
        )
        live_scope = db.get(CorrelationScope, "live")
        frontier = now - timedelta(seconds=ALLOWED_LATENESS_SECONDS)
        if (
            live_scope is not None
            and not undiscovered
            and not unknown_input
            and (live_scope.watermark is None or frontier > live_scope.watermark)
        ):
            live_scope.watermark = frontier
        db.commit()
    return counts
