"""PostgreSQL owns delivery, bounded retries and fenced staging state transitions.

Redis may lose a publication or deliver it repeatedly. Both are safe: each unfinished
row stays eligible for a later sweep, while only the current worker token may finish.
No transaction or row lock is held during broker I/O or payload processing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import or_, select, update

from app.core.config import Settings
from app.infrastructure.database import Database, utcnow
from app.modules.ingestion.models import OutboxJob, RawEvent
from app.modules.ingestion.schemas import RawEnvelope, canonical_json

_UNFINISHED = ("pending", "processing")
_PERMANENT_CODES = frozenset(
    {"integrity_mismatch", "invalid_payload", "empty_payload", "invalid_json"}
)


class TransientProcessingError(Exception):
    """A processor could not finish now; exception text is never retained."""


class PermanentProcessingError(Exception):
    """Only bounded, public error codes can reach persistent job metadata."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _PERMANENT_CODES else "invalid_payload"
        super().__init__(self.code)


@dataclass(frozen=True, repr=False)
class EventSnapshot:
    event_id: UUID
    envelope: dict[str, Any]
    payload_hash: str
    payload_bytes: int
    source_type: str


@dataclass(frozen=True)
class DispatchResult:
    claimed: int = 0
    published: int = 0
    failed: int = 0
    quarantined: int = 0


@dataclass(frozen=True)
class _DispatchClaim:
    event_id: UUID
    generation: int
    token: UUID
    attempt: int


def retry_delay(settings: Settings, attempt: int) -> int:
    """Bound both exponent work and retry interval, even for malformed counters."""
    exponent = max(0, min(attempt - 1, 30))
    return min(settings.ingest_retry_max_seconds, settings.ingest_retry_base_seconds << exponent)


def _reject_json_constant(value: str) -> None:
    raise ValueError("nonfinite JSON number")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def validate_raw_event(event: EventSnapshot) -> None:
    """Verify the immutable inbox record and stage only supported content shapes."""
    try:
        encoded = canonical_json(event.envelope)
        if len(encoded) != event.payload_bytes or not hmac.compare_digest(
            hashlib.sha256(encoded).hexdigest(), event.payload_hash
        ):
            raise PermanentProcessingError("integrity_mismatch")
        envelope = RawEnvelope.model_validate(event.envelope)
        if envelope.source_type != event.source_type:
            raise PermanentProcessingError("integrity_mismatch")
    except (TypeError, ValueError, RecursionError, ValidationError):
        raise PermanentProcessingError("invalid_payload") from None
    raw = envelope.raw_event
    if isinstance(raw, str):
        if not raw.strip():
            raise PermanentProcessingError("empty_payload")
        if event.source_type == "generic_json":
            try:
                parsed = json.loads(
                    raw,
                    parse_constant=_reject_json_constant,
                    object_pairs_hook=_unique_json_object,
                )
                if not isinstance(parsed, dict):
                    raise ValueError("JSON object required")
                # Reuse intake's depth/size/type rules for JSON carried as a string.
                RawEnvelope.model_validate({"source_type": "generic_json", "raw_event": parsed})
            except (ValueError, TypeError, RecursionError):
                raise PermanentProcessingError("invalid_json") from None


def dispatch_once(
    database: Database, settings: Settings, publish: Callable[[str, int], None]
) -> DispatchResult:
    """Claim a bounded sweep, commit, publish IDs, then acknowledge each token.

    Counting attempts when claiming bounds crashes before/after publication too.
    A successful publication is deliberately not a terminal database state.
    """
    claims: list[_DispatchClaim] = []
    quarantined = 0
    now = utcnow()
    with database.sessions() as session:
        jobs = session.scalars(
            select(OutboxJob)
            .where(
                OutboxJob.state.in_(_UNFINISHED),
                OutboxJob.available_at <= now,
                or_(OutboxJob.dispatch_until.is_(None), OutboxJob.dispatch_until <= now),
                or_(OutboxJob.worker_until.is_(None), OutboxJob.worker_until <= now),
            )
            .order_by(OutboxJob.available_at, OutboxJob.event_id)
            .limit(settings.ingest_dispatch_batch_size)
            .with_for_update(skip_locked=True)
        ).all()
        for job in jobs:
            if job.dispatch_attempts >= settings.ingest_max_dispatch_attempts:
                _quarantine(job, "dispatch_exhausted")
                quarantined += 1
                continue
            token = uuid4()
            job.dispatch_attempts += 1
            job.dispatch_token = token
            job.dispatch_until = now + timedelta(seconds=settings.ingest_dispatch_lease_seconds)
            # A due processing retry has served its durable backoff. The next
            # available_at written by the relay is only a publication sweep time.
            if job.last_error_code == "processing_failed":
                job.last_error_code = None
            claims.append(
                _DispatchClaim(job.event_id, job.generation, token, job.dispatch_attempts)
            )
        session.commit()

    published = failed = 0
    for claim in claims:
        success = False
        try:
            publish(str(claim.event_id), claim.generation)
            success = True
            published += 1
        except Exception:
            # Broker/driver exceptions often contain credentials; never persist their text.
            failed += 1
        with database.sessions() as session:
            acknowledged = session.scalar(
                select(OutboxJob)
                .where(
                    OutboxJob.event_id == claim.event_id,
                    OutboxJob.generation == claim.generation,
                    OutboxJob.dispatch_token == claim.token,
                    OutboxJob.state.in_(_UNFINISHED),
                )
                .with_for_update()
            )
            if acknowledged is not None:
                acknowledged.dispatch_token = None
                acknowledged.dispatch_until = None
                if not success and claim.attempt >= settings.ingest_max_dispatch_attempts:
                    _quarantine(acknowledged, "dispatch_exhausted")
                    quarantined += 1
                else:
                    delay = (
                        settings.ingest_redelivery_seconds
                        if success
                        else retry_delay(settings, claim.attempt)
                    )
                    acknowledged.available_at = utcnow() + timedelta(seconds=delay)
                    if not success:
                        acknowledged.last_error_code = "dispatch_failed"
            session.commit()
    return DispatchResult(len(claims), published, failed, quarantined)


def _quarantine(job: OutboxJob, code: str) -> None:
    job.state = "quarantined"
    job.last_error_code = code
    job.completed_at = utcnow()
    job.dispatch_token = None
    job.dispatch_until = None
    job.worker_token = None
    job.worker_until = None


def process_event(
    database: Database,
    settings: Settings,
    event_id: UUID,
    generation: int,
    *,
    processor: Callable[[EventSnapshot], None] | None = None,
) -> str:
    """Claim one generation, validate outside its transaction and finish by CAS.

    The optional additional processor permits controlled transient-failure tests;
    it never bypasses the standard integrity and content validation.
    """
    now = utcnow()
    token = uuid4()
    with database.sessions() as session:
        job = session.scalar(
            select(OutboxJob).where(OutboxJob.event_id == event_id).with_for_update()
        )
        if job is None:
            return "missing"
        if job.generation != generation:
            return "stale"
        if job.state not in _UNFINISHED:
            return "duplicate"
        if job.worker_until is not None and job.worker_until > now:
            return "busy"
        if job.state == "pending" and job.available_at > now:
            # A broker duplicate must not circumvent a durable processing backoff.
            # Successful relay publication also schedules the next sweep, so only
            # an actual processing error makes available_at a worker admission gate.
            if job.last_error_code in {"processing_failed", "processing_exhausted"}:
                return "busy"
        if job.attempts >= settings.ingest_max_processing_attempts:
            _quarantine(job, "processing_exhausted")
            session.commit()
            return "quarantined"
        raw = session.get(RawEvent, event_id)
        if raw is None:
            _quarantine(job, "integrity_mismatch")
            session.commit()
            return "quarantined"
        snapshot = EventSnapshot(
            raw.id, raw.envelope, raw.payload_hash, raw.payload_bytes, raw.source_type
        )
        job.attempts += 1
        attempt = job.attempts
        job.state = "processing"
        job.worker_token = token
        job.worker_until = now + timedelta(seconds=settings.ingest_worker_lease_seconds)
        # A late relay ack must not change a processing or terminal job.
        job.dispatch_token = None
        job.dispatch_until = None
        session.commit()

    state = "staged"
    error_code: str | None = None
    try:
        validate_raw_event(snapshot)
        if processor is not None:
            processor(snapshot)
    except PermanentProcessingError as error:
        state, error_code = "quarantined", error.code
    except Exception:
        # Unexpected processor failures are retryable, bounded and redacted too.
        if attempt >= settings.ingest_max_processing_attempts:
            state, error_code = "quarantined", "processing_exhausted"
        else:
            state, error_code = "pending", "processing_failed"

    finished_at = utcnow()
    with database.sessions() as session:
        changed = session.execute(
            update(OutboxJob)
            .where(
                OutboxJob.event_id == event_id,
                OutboxJob.generation == generation,
                OutboxJob.worker_token == token,
                OutboxJob.state == "processing",
            )
            .values(
                state=state,
                last_error_code=error_code,
                completed_at=finished_at if state != "pending" else None,
                available_at=finished_at + timedelta(seconds=retry_delay(settings, attempt)),
                worker_token=None,
                worker_until=None,
                dispatch_token=None,
                dispatch_until=None,
            )
            .returning(OutboxJob.event_id)
        ).scalar_one_or_none()
        session.commit()
    return state if changed is not None else "stale"
