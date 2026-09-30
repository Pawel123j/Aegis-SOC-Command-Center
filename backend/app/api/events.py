"""Durable source-authenticated admission and bounded processing status."""

import re
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Response
from sqlalchemy import func, select

from app.api.dependencies import DB, Principal, current_principal, require
from app.api.sources import SourceAdmin
from app.api.users import lock_administration
from app.core.errors import ApiError, unauthorized
from app.core.permissions import Permission, has_permission
from app.core.rate_limit import rate_limit
from app.core.security import token_hash, utcnow
from app.modules.audit.service import append_audit
from app.modules.ingestion.models import (
    BatchEvent,
    IngestCapacity,
    IngestionBatch,
    IngestionSource,
    OutboxJob,
    RawEvent,
    SourceCredential,
)
from app.modules.ingestion.schemas import EnvelopeBatch, RawEnvelope
from app.modules.ingestion.service import accept_batch

router = APIRouter(prefix="/api/v1/events", tags=["ingestion"])
system_router = APIRouter(prefix="/api/v1/system", tags=["system"])
SOURCE_TOKEN = re.compile(r"aegis_ingest_[A-Za-z0-9_-]{43}\Z")
IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")


@dataclass
class SourcePrincipal:
    source: IngestionSource
    credential: SourceCredential


def source_principal(request: Request, db: DB, scope: str, *, writing: bool) -> SourcePrincipal:
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer ") or not SOURCE_TOKEN.fullmatch(authorization[7:]):
        raise unauthorized()
    credential = db.scalar(
        select(SourceCredential).where(
            SourceCredential.secret_hash == token_hash(authorization[7:])
        )
    )
    if credential is None:
        raise unauthorized()
    # Source then credential is also the administrator's lock order. The shared
    # locks linearize admission against revocation/disable until admission commits.
    query = select(IngestionSource).where(IngestionSource.id == credential.source_id)
    if writing:
        query = query.with_for_update(read=True)
    source = db.scalar(query.execution_options(populate_existing=True))
    if writing:
        credential = db.scalar(
            select(SourceCredential)
            .where(SourceCredential.id == credential.id)
            .with_for_update(read=True)
            .execution_options(populate_existing=True)
        )
    if (
        source is None
        or not source.enabled
        or credential is None
        or credential.revoked_at is not None
        or credential.expires_at <= utcnow()
    ):
        raise unauthorized()
    if scope not in credential.scopes:
        raise ApiError(403, "forbidden", "Permission denied")
    return SourcePrincipal(source, credential)


@router.post("", status_code=202)
def ingest(
    data: RawEnvelope | EnvelopeBatch,
    request: Request,
    response: Response,
    db: DB,
    idempotency_key: Annotated[str | None, Header()] = None,
) -> dict[str, object]:
    principal = source_principal(request, db, "events:write", writing=True)
    if idempotency_key is None or not IDEMPOTENCY_KEY.fullmatch(idempotency_key):
        raise ApiError(422, "idempotency_key_required", "A valid Idempotency-Key is required")
    rate_limit(request, "ingest-source", str(principal.source.id), 10, window_seconds=1)
    envelopes = data.events if isinstance(data, EnvelopeBatch) else [data]
    batch = accept_batch(
        db,
        principal.source,
        envelopes,
        idempotency_key,
        request.state.request_id,
        request.app.state.settings,
    )
    # The service writes acceptance audit only for a new durable receipt, in this transaction.
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Location"] = f"/api/v1/events/batches/{batch.id}"
    return {
        "batch_id": batch.id,
        "accepted_count": batch.accepted_count,
        "created_count": batch.created_count,
        "duplicate_count": batch.duplicate_count,
        "status_url": f"/api/v1/events/batches/{batch.id}",
        "request_id": batch.request_id,
    }


@router.get("/batches/{batch_id}")
def batch_status(batch_id: UUID, request: Request, response: Response, db: DB) -> dict[str, object]:
    query = select(IngestionBatch).where(IngestionBatch.id == batch_id)
    if request.headers.get("authorization", "").startswith("Bearer aegis_ingest_"):
        principal = source_principal(request, db, "events:status", writing=False)
        query = query.where(
            IngestionBatch.source_id == principal.source.id,
            IngestionBatch.dataset_id == principal.source.dataset_id,
            IngestionBatch.mode == principal.source.mode,
            IngestionBatch.run_id == principal.source.run_id,
        )
    else:
        human = current_principal(request, db)
        if not has_permission(human.user.role, Permission.EVENTS_READ):
            raise ApiError(403, "forbidden", "Permission denied")
    batch = db.scalar(query)
    if batch is None:
        raise ApiError(404, "not_found", "Batch not found")
    records = db.execute(
        select(BatchEvent.position, OutboxJob)
        .join(OutboxJob, OutboxJob.event_id == BatchEvent.event_id)
        .where(BatchEvent.batch_id == batch_id)
        .order_by(BatchEvent.position)
        .limit(500)
    ).all()
    counts = {state: 0 for state in ("pending", "processing", "staged", "quarantined")}
    items = []
    for position, job in records:
        counts[job.state] += 1
        items.append(
            {
                "position": position,
                "event_id": job.event_id,
                "state": job.state,
                "generation": job.generation,
                "attempts": job.attempts,
                "error_code": job.last_error_code,
            }
        )
    response.headers["Cache-Control"] = "no-store"
    return {
        "batch_id": batch.id,
        "accepted_count": batch.accepted_count,
        "created_count": batch.created_count,
        "duplicate_count": batch.duplicate_count,
        "counts": {**counts, "normalized": 0, "processed": 0, "projected": 0},
        "records": items,
        "request_id": batch.request_id,
    }


@router.post("/{event_id}/retry")
def retry_event(
    event_id: UUID,
    request: Request,
    response: Response,
    db: DB,
    principal: SourceAdmin,
    if_match: Annotated[str | None, Header()] = None,
) -> dict[str, object]:
    if if_match is None:
        raise ApiError(428, "version_required", "If-Match is required")
    lock_administration(db, principal)
    # Admission and manual retries share the same serialization point. Take this
    # before the job lock so a retry cannot overfill the bounded pending backlog.
    capacity = db.scalar(select(IngestCapacity).where(IngestCapacity.id == 1).with_for_update())
    if capacity is None:
        raise ApiError(503, "ingest_capacity_unavailable", "Service temporarily unavailable")
    job = db.scalar(select(OutboxJob).where(OutboxJob.event_id == event_id).with_for_update())
    if job is None:
        raise ApiError(404, "not_found", "Event not found")
    if if_match != f'"{job.generation}"':
        raise ApiError(412, "version_conflict", "Refresh the resource before retrying")
    if job.state != "quarantined":
        raise ApiError(409, "retry_not_allowed", "Only quarantined events can be retried")
    pending = (
        db.scalar(
            select(func.count())
            .select_from(OutboxJob)
            .where(OutboxJob.state.in_(["pending", "processing"]))
        )
        or 0
    )
    if pending >= request.app.state.settings.ingest_max_pending_events:
        raise ApiError(
            503, "ingest_backpressure", "Service temporarily unavailable", {"Retry-After": "5"}
        )
    raw = db.get(RawEvent, event_id)
    if raw is None:
        raise ApiError(409, "retry_not_allowed", "Event data unavailable")
    job.generation += 1
    job.state = "pending"
    job.attempts = 0
    job.dispatch_attempts = 0
    job.available_at = utcnow()
    job.completed_at = None
    job.last_error_code = None
    job.dispatch_token = None
    job.dispatch_until = None
    job.worker_token = None
    job.worker_until = None
    append_audit(
        db,
        action="events.retried",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=principal.user.id,
        object_type="event",
        object_id=str(event_id),
        details={"source_id": str(raw.source_id), "generation": job.generation},
    )
    db.commit()
    response.headers.update({"Cache-Control": "no-store", "ETag": f'"{job.generation}"'})
    return {"event_id": event_id, "state": job.state, "generation": job.generation}


@system_router.get("/ingestion")
def ingestion_capacity(
    request: Request,
    response: Response,
    db: DB,
    principal: Annotated[Principal, Depends(require(Permission.SYSTEM_READ))],
) -> dict[str, object]:
    capacity = db.get(IngestCapacity, 1)
    if capacity is None:
        raise ApiError(503, "ingest_capacity_unavailable", "Service temporarily unavailable")
    grouped = db.execute(select(OutboxJob.state, func.count()).group_by(OutboxJob.state)).all()
    counts = {state: 0 for state in ("pending", "processing", "staged", "quarantined")}
    counts.update({state: count for state, count in grouped})
    oldest = db.scalar(
        select(func.min(OutboxJob.created_at)).where(OutboxJob.state.in_(["pending", "processing"]))
    )
    settings = request.app.state.settings
    response.headers["Cache-Control"] = "no-store"
    return {
        "retained_events": capacity.event_count,
        "receipt_records": capacity.receipt_count,
        "payload_bytes": capacity.byte_count,
        "states": counts,
        "oldest_pending_seconds": max(0, int((utcnow() - oldest).total_seconds())) if oldest else 0,
        "limits": {
            "stored_events": settings.ingest_max_stored_events,
            "receipt_records": settings.ingest_max_receipt_records,
            "payload_bytes": settings.ingest_max_stored_bytes,
            "pending_events": settings.ingest_max_pending_events,
            "oldest_pending_seconds": settings.ingest_max_oldest_pending_seconds,
        },
    }
