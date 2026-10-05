"""Durable normalization and projection; no SQL lock spans parser or network I/O."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import exists, or_, select
from sqlalchemy.dialects.postgresql import insert

from app.core.config import Settings
from app.infrastructure.database import Database, utcnow
from app.modules.entities.indexing import index_event
from app.modules.ingestion.models import IngestionSource, OutboxJob, RawEvent
from app.modules.ingestion.processing import (
    EventSnapshot,
    PermanentProcessingError,
    retry_delay,
    validate_raw_event,
)
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.models import NormalizedEvent, PipelineJob
from app.modules.normalization.parsers import NormalizationContext, NormalizationError, normalize


@dataclass(frozen=True)
class Claim:
    event_id: UUID
    token: UUID
    stage: str
    attempt: int


def enqueue_staged(database: Database, limit: int) -> int:
    """Backfill old staged events too; concurrent sweeps share a unique event ID."""
    with database.sessions() as session:
        candidates = (
            select(OutboxJob.event_id)
            .where(
                OutboxJob.state == "staged",
                ~exists(
                    select(PipelineJob.event_id).where(PipelineJob.event_id == OutboxJob.event_id)
                ),
            )
            .order_by(OutboxJob.event_id)
            .limit(limit)
        )
        result = session.execute(
            insert(PipelineJob)
            .from_select(["event_id"], candidates, include_defaults=False)
            .on_conflict_do_nothing(index_elements=[PipelineJob.event_id])
            .returning(PipelineJob.event_id)
        ).all()
        session.commit()
        return len(result)


def claim_one(database: Database, settings: Settings) -> Claim | None:
    now = utcnow()
    with database.sessions() as session:
        job = session.scalar(
            select(PipelineJob)
            .where(
                PipelineJob.state.in_(["pending", "normalizing", "normalized", "projecting"]),
                PipelineJob.available_at <= now,
                or_(PipelineJob.lease_until.is_(None), PipelineJob.lease_until <= now),
            )
            .order_by(PipelineJob.available_at, PipelineJob.event_id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if job is None:
            return None
        stage = "normalizing" if job.state in {"pending", "normalizing"} else "projecting"
        attempts = job.normalization_attempts if stage == "normalizing" else job.projection_attempts
        maximum = (
            settings.pipeline_max_normalization_attempts
            if stage == "normalizing"
            else settings.pipeline_max_projection_attempts
        )
        if attempts >= maximum:
            job.state = "quarantined" if stage == "normalizing" else "projection_failed"
            job.last_error_code = (
                "normalization_exhausted" if stage == "normalizing" else "projection_exhausted"
            )
            job.lease_token = None
            job.lease_until = None
            job.completed_at = now
            session.commit()
            return None
        token = uuid4()
        job.state = stage
        job.lease_token = token
        job.lease_until = now + timedelta(seconds=settings.pipeline_lease_seconds)
        if stage == "normalizing":
            job.normalization_attempts += 1
        else:
            job.projection_attempts += 1
        session.commit()
        return Claim(job.event_id, token, stage, attempts + 1)


def run_claim(
    database: Database,
    settings: Settings,
    claim: Claim,
    project: Callable[[dict[str, Any]], None],
) -> str:
    document: dict[str, Any] | None = None
    error: str | None = None
    permanent = False
    try:
        with database.sessions() as session:
            raw = session.get(RawEvent, claim.event_id)
            if raw is None:
                raise NormalizationError("integrity_mismatch")
            if claim.stage == "normalizing":
                source = session.get(IngestionSource, raw.source_id)
                if source is None:
                    raise NormalizationError("integrity_mismatch")
                snapshot = EventSnapshot(
                    raw.id, raw.envelope, raw.payload_hash, raw.payload_bytes, raw.source_type
                )
                context = NormalizationContext(
                    event_id=raw.id,
                    source_id=raw.source_id,
                    dataset_id=raw.dataset_id,
                    run_id=raw.run_id,
                    source_event_id=raw.source_event_id,
                    mode=raw.mode,
                    source_name=source.name,
                    source_type=raw.source_type,
                    timezone=source.timezone,
                    received_at=raw.received_at,
                    processed_at=utcnow(),
                    raw_sha256=raw.payload_hash,
                )
                envelope = raw.envelope
            else:
                stored = session.get(NormalizedEvent, raw.id)
                if stored is None:
                    raise NormalizationError("integrity_mismatch")
                document = stored.document
                if not hmac.compare_digest(
                    hashlib.sha256(canonical_json(document)).hexdigest(), stored.document_sha256
                ):
                    raise NormalizationError("integrity_mismatch")
        if claim.stage == "normalizing":
            validate_raw_event(snapshot)
            document = normalize(envelope, context).model_dump(mode="json")
        elif document is not None:
            project(document)
    except (NormalizationError, PermanentProcessingError) as failure:
        error, permanent = failure.code, True
    except Exception:
        # Parser, SQL and HTTP exceptions may include raw content or credentials.
        error = "normalization_failed" if claim.stage == "normalizing" else "projection_unavailable"

    with database.sessions() as session:
        job = session.scalar(
            select(PipelineJob).where(PipelineJob.event_id == claim.event_id).with_for_update()
        )
        if job is None or job.lease_token != claim.token or job.state != claim.stage:
            return "stale"
        now = utcnow()
        if error is None and document is not None:
            if claim.stage == "normalizing":
                # Snapshot and progress commit together, only under the current lease.
                normalized = normalize_timestamp(document["timestamp"])
                processed = normalize_timestamp(document["processed_at"])
                stored = NormalizedEvent(
                    event_id=claim.event_id,
                    timestamp=normalized,
                    processed_at=processed,
                    schema_version=document["schema_version"],
                    parser_version=document["parser_version"],
                    document=document,
                    document_sha256=hashlib.sha256(canonical_json(document)).hexdigest(),
                )
                session.add(stored)
                session.flush()
                index_event(session, stored)
                job.state = "normalized"
            else:
                job.state = "projected"
                job.completed_at = now
            job.last_error_code = None
            job.available_at = now
        else:
            maximum = (
                settings.pipeline_max_normalization_attempts
                if claim.stage == "normalizing"
                else settings.pipeline_max_projection_attempts
            )
            terminal = permanent or claim.attempt >= maximum
            job.state = (
                ("quarantined" if claim.stage == "normalizing" else "projection_failed")
                if terminal
                else ("pending" if claim.stage == "normalizing" else "normalized")
            )
            job.last_error_code = error or "normalization_failed"
            job.completed_at = now if terminal else None
            job.available_at = now + timedelta(seconds=retry_delay(settings, claim.attempt))
        job.lease_token = None
        job.lease_until = None
        session.commit()
        return job.state


def normalize_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def process_once(
    database: Database, settings: Settings, project: Callable[[dict[str, Any]], None]
) -> dict[str, int]:
    enqueue_staged(database, settings.pipeline_batch_size)
    counts: dict[str, int] = {}
    for _ in range(settings.pipeline_batch_size):
        claim = claim_one(database, settings)
        if claim is None:
            break
        state = run_claim(database, settings, claim, project)
        counts[state] = counts.get(state, 0) + 1
    return counts
