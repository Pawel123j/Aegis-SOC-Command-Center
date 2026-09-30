"""One transaction admits complete batches into PostgreSQL and the durable outbox."""

import hashlib
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import ApiError
from app.infrastructure.database import utcnow
from app.modules.audit.service import append_audit
from app.modules.ingestion.models import (
    BatchEvent,
    IngestCapacity,
    IngestionBatch,
    IngestionSource,
    OutboxJob,
    RawEvent,
)
from app.modules.ingestion.schemas import (
    RawEnvelope,
    batch_hash,
    canonical_envelope,
    canonical_json,
)


def _backpressure() -> ApiError:
    return ApiError(
        503,
        "ingest_backpressure",
        "Ingestion capacity is temporarily unavailable",
        {"Retry-After": "5"},
    )


def accept_batch(
    db: Session,
    source: IngestionSource,
    envelopes: list[RawEnvelope],
    idempotency_key: str,
    request_id: str,
    settings: Settings,
) -> IngestionBatch:
    """Flush admission and acceptance audit; the caller owns commit and rollback.

    The singleton lock serializes all admissions, including deduplication and capacity
    checks. No broker communication occurs inside or after this service.
    """
    if not 1 <= len(envelopes) <= 500:
        raise ApiError(422, "invalid_batch", "A batch must contain 1 to 500 events")
    payload_hash = batch_hash(envelopes)
    capacity = db.scalar(select(IngestCapacity).where(IngestCapacity.id == 1).with_for_update())
    if capacity is None:
        raise ApiError(503, "ingest_capacity_unavailable", "Ingestion is unavailable")

    scope = {
        "source_id": source.id,
        "dataset_id": source.dataset_id,
        "mode": source.mode,
        "run_id": source.run_id,
    }
    existing_batch = db.scalar(
        select(IngestionBatch).filter_by(**scope, idempotency_key=idempotency_key)
    )
    if existing_batch is not None:
        if existing_batch.payload_hash != payload_hash:
            raise ApiError(
                409, "idempotency_conflict", "Idempotency key already has different content"
            )
        return existing_batch

    if any(item.source_type.value not in source.source_types for item in envelopes):
        raise ApiError(422, "source_type_not_allowed", "Source type is not enabled for this source")

    # Every new request has durable receipts, even if all raw events deduplicate.
    if capacity.receipt_count + len(envelopes) > settings.ingest_max_receipt_records:
        raise _backpressure()

    event_keys = {item.source_event_id for item in envelopes if item.source_event_id is not None}
    known = (
        {
            event.source_event_id: event
            for event in db.scalars(
                select(RawEvent).filter_by(**scope).where(RawEvent.source_event_id.in_(event_keys))
            )
        }
        if event_keys
        else {}
    )
    new_events: list[RawEvent] = []
    ordered_events: list[RawEvent] = []
    now = utcnow()
    for envelope in envelopes:
        body = canonical_envelope(envelope)
        body_bytes = canonical_json(body)
        event_hash = hashlib.sha256(body_bytes).hexdigest()
        existing = (
            known.get(envelope.source_event_id) if envelope.source_event_id is not None else None
        )
        if existing is not None:
            if existing.payload_hash != event_hash:
                raise ApiError(
                    409, "event_id_conflict", "Source event ID already has different content"
                )
            ordered_events.append(existing)
            continue
        event = RawEvent(
            id=uuid4(),
            **scope,
            source_event_id=envelope.source_event_id,
            source_type=envelope.source_type.value,
            envelope=body,
            payload_hash=event_hash,
            payload_bytes=len(body_bytes),
            received_at=now,
            request_id=request_id,
        )
        new_events.append(event)
        ordered_events.append(event)
        if envelope.source_event_id is not None:
            known[envelope.source_event_id] = event

    new_bytes = sum(event.payload_bytes for event in new_events)
    if new_events:
        pending_count, oldest = db.execute(
            select(func.count(), func.min(OutboxJob.created_at))
            .select_from(OutboxJob)
            .where(OutboxJob.state.in_(("pending", "processing")))
        ).one()
        if (
            capacity.event_count + len(new_events) > settings.ingest_max_stored_events
            or capacity.byte_count + new_bytes > settings.ingest_max_stored_bytes
            or pending_count + len(new_events) > settings.ingest_max_pending_events
            or (
                oldest is not None
                and now - oldest > timedelta(seconds=settings.ingest_max_oldest_pending_seconds)
            )
        ):
            raise _backpressure()

    batch = IngestionBatch(
        id=uuid4(),
        **scope,
        idempotency_key=idempotency_key,
        payload_hash=payload_hash,
        received_at=now,
        request_id=request_id,
        accepted_count=len(envelopes),
        created_count=len(new_events),
        duplicate_count=len(envelopes) - len(new_events),
    )
    db.add(batch)
    db.add_all(new_events)
    db.flush()
    db.add_all(
        OutboxJob(event_id=event.id, created_at=now, available_at=now) for event in new_events
    )
    db.add_all(
        BatchEvent(batch_id=batch.id, position=position, event_id=event.id)
        for position, event in enumerate(ordered_events)
    )
    capacity.event_count += len(new_events)
    capacity.byte_count += new_bytes
    capacity.receipt_count += len(envelopes)
    append_audit(
        db,
        action="events.accepted",
        outcome="success",
        request_id=request_id,
        object_type="ingestion_batch",
        object_id=str(batch.id),
        details={
            "source_id": str(source.id),
            "accepted_count": batch.accepted_count,
            "created_count": batch.created_count,
        },
    )
    db.flush()
    return batch
