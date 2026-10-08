"""Recoverable PostgreSQL queue: fenced leases and one transaction per local effect."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import func, or_, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.infrastructure.database import ADMIN_LOCK_ID, Database
from app.modules.alerts.models import Alert
from app.modules.ingestion.schemas import canonical_json
from app.modules.soar.actions import execute_action
from app.modules.soar.evidence import alert_record, verify_context
from app.modules.soar.models import (
    Playbook,
    PlaybookAttempt,
    PlaybookEffect,
    PlaybookRevision,
    PlaybookRun,
    PlaybookStep,
)
from app.modules.soar.schemas import ENGINE_VERSION, MAX_OUTPUT_BYTES, digest
from app.modules.soar.service import TERMINAL, audit, authorize_actions, verified_revision
from app.modules.users.models import User


@dataclass(frozen=True)
class Claim:
    run_id: UUID
    step_id: UUID
    token: int


class TransientActionError(Exception):
    """Only an explicitly classified temporary local failure is retryable."""


def lock_authority(db: Session) -> None:
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": ADMIN_LOCK_ID})


def clock(db: Session) -> datetime:
    value = db.scalar(select(func.clock_timestamp()))
    assert isinstance(value, datetime)
    return value


def attempt(db: Session, step: PlaybookStep, now: datetime, outcome: str, code: str | None) -> None:
    assert step.started_at is not None
    db.add(
        PlaybookAttempt(
            step_id=step.id,
            number=step.attempts,
            started_at=step.started_at,
            finished_at=now,
            outcome=outcome,
            error_code=code,
        )
    )


def stop_run(
    db: Session, run: PlaybookRun, now: datetime, code: str, *, cancelled: bool = False
) -> None:
    if run.state in TERMINAL:
        return
    active = db.scalar(
        select(PlaybookStep).where(PlaybookStep.run_id == run.id, PlaybookStep.state == "running")
    )
    if active is not None:
        attempt(db, active, now, "cancelled" if cancelled else "failed", code)
        active.state = "failed"
        active.error_code, active.finished_at, active.lease_until = code, now, None
    run.state = "cancelled" if cancelled else "failed"
    run.error_code, run.finished_at = code, now
    audit(db, f"run_{run.state}", run.id, run.requested_by, {"error_code": code}, str(run.id))


def guard(db: Session, run: PlaybookRun) -> tuple[User, Alert]:
    row = db.get(PlaybookRevision, run.revision_id)
    book = db.get(Playbook, row.playbook_id) if row else None
    actor = db.get(User, run.requested_by)
    if row is None or book is None or not book.enabled:
        raise ApiError(409, "soar_disabled", "Playbook disabled")
    if actor is None:
        raise ApiError(403, "soar_authority_revoked", "Workflow actor unavailable")
    definition = verified_revision(row)
    authorize_actions(actor, definition)
    if (
        run.execution_mode != "simulation"
        or digest(run.context) != run.context_sha256
        or run.context.get("mode") != run.mode
        or run.context.get("dataset_id") != str(run.dataset_id)
        or run.context.get("data_run_id") != str(run.data_run_id)
    ):
        raise ApiError(409, "soar_context_integrity", "Workflow scope proof is invalid")
    steps = list(
        db.scalars(
            select(PlaybookStep)
            .where(PlaybookStep.run_id == run.id)
            .order_by(PlaybookStep.position)
        )
    )
    if len(steps) != len(definition.steps):
        raise ApiError(409, "soar_steps_integrity", "Workflow steps are invalid")
    for index, (stored, expected) in enumerate(zip(steps, definition.steps, strict=True)):
        if (
            stored.position != index
            or stored.step_id != expected.id
            or stored.action != expected.action
            or stored.input_sha256
            != digest(
                {
                    "context": run.context_sha256,
                    "step": expected.model_dump(),
                    "engine": ENGINE_VERSION,
                }
            )
        ):
            raise ApiError(409, "soar_steps_integrity", "Workflow step proof is invalid")
    alert = alert_record(db, run.alert_id)
    verify_context(alert, run.context)
    if alert.status == "false_positive":
        raise ApiError(409, "soar_false_positive", "Alert requires review")
    return actor, alert


def claim_next(database: Database) -> Claim | None:
    with database.sessions() as db:
        lock_authority(db)
        now = clock(db)
        run = db.scalar(
            select(PlaybookRun)
            .where(
                PlaybookRun.state.not_in(TERMINAL),
                or_(
                    PlaybookRun.next_attempt_at <= now,
                    PlaybookRun.deadline_at <= now,
                    PlaybookRun.cancellation_requested.is_(True),
                ),
            )
            .order_by(PlaybookRun.next_attempt_at, PlaybookRun.created_at, PlaybookRun.id)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        if run is None:
            return None
        if run.cancellation_requested or run.deadline_at <= now:
            stop_run(
                db,
                run,
                now,
                "soar_cancelled" if run.cancellation_requested else "soar_deadline",
                cancelled=run.cancellation_requested,
            )
            db.commit()
            return None
        try:
            guard(db, run)
        except (ApiError, ValueError, TypeError, KeyError) as error:
            stop_run(
                db,
                run,
                now,
                error.code if isinstance(error, ApiError) else "soar_context_integrity",
            )
            db.commit()
            return None
        step = db.scalar(
            select(PlaybookStep)
            .where(PlaybookStep.run_id == run.id, PlaybookStep.state != "completed")
            .order_by(PlaybookStep.position)
            .limit(1)
            .with_for_update()
        )
        if step is None:
            # Completion is normally atomic with the last effect. Fail closed if
            # an inconsistent nonterminal run was written outside the service.
            stop_run(db, run, now, "soar_steps_integrity")
            db.commit()
            return None
        if step.state == "running":
            if step.lease_until is not None and step.lease_until > now:
                return None
            attempt(db, step, now, "expired", "soar_lease_expired")
            step.state, step.lease_until = "waiting", None
            db.flush()
        if step.attempts >= 3 or step.state == "failed":
            step.state, step.finished_at, step.error_code = "failed", now, "soar_attempts_exhausted"
            stop_run(db, run, now, "soar_attempts_exhausted")
            db.commit()
            return None
        step.attempts += 1
        step.state, step.started_at, step.error_code = "running", now, None
        step.lease_until = min(now + timedelta(seconds=30), run.deadline_at)
        run.state, run.next_attempt_at = "running", step.lease_until
        run.started_at = run.started_at or now
        audit(
            db,
            "step_started",
            run.id,
            run.requested_by,
            {"step": step.step_id, "attempt": step.attempts},
            str(run.id),
        )
        result = Claim(run.id, step.id, step.attempts)
        db.commit()
        return result


def load_claim(db: Session, claim: Claim) -> tuple[PlaybookRun, PlaybookStep] | None:
    lock_authority(db)
    run = db.scalar(select(PlaybookRun).where(PlaybookRun.id == claim.run_id).with_for_update())
    step = db.get(PlaybookStep, claim.step_id)
    now = clock(db)
    if (
        run is None
        or step is None
        or step.run_id != run.id
        or run.state in TERMINAL
        or step.state != "running"
        or step.attempts != claim.token
        or step.lease_until is None
        or step.lease_until <= now
    ):
        return None
    if run.cancellation_requested or run.deadline_at <= now:
        stop_run(
            db,
            run,
            now,
            "soar_cancelled" if run.cancellation_requested else "soar_deadline",
            cancelled=run.cancellation_requested,
        )
        db.commit()
        return None
    return run, step


def record_failure(database: Database, claim: Claim, code: str, *, retryable: bool) -> None:
    with database.sessions() as db:
        loaded = load_claim(db, claim)
        if loaded is None:
            return
        run, step = loaded
        now = clock(db)
        attempt(db, step, now, "failed", code)
        step.error_code, step.lease_until = code, None
        step.state = "waiting" if retryable and step.attempts < 3 else "failed"
        step.finished_at = now if step.state == "failed" else None
        if step.state == "waiting":
            run.next_attempt_at = now + timedelta(seconds=5 if step.attempts == 1 else 20)
        else:
            db.flush()
            stop_run(db, run, now, code)
        audit(
            db,
            "step_failed",
            run.id,
            run.requested_by,
            {
                "step": step.step_id,
                "attempt": step.attempts,
                "error_code": code,
                "retry": step.state == "waiting",
            },
            str(run.id),
        )
        db.commit()


def execute_claim(database: Database, claim: Claim) -> bool:
    try:
        with database.sessions() as db:
            loaded = load_claim(db, claim)
            if loaded is None:
                return False
            run, step = loaded
            actor, alert = guard(db, run)
            if db.get(PlaybookEffect, step.id) is not None:
                raise ApiError(409, "soar_effect_integrity", "Unexpected prior effect")
            output = execute_action(db, run, step, alert, actor)
            if len(canonical_json(output)) > MAX_OUTPUT_BYTES // 2:
                raise ApiError(409, "soar_output_limit", "Workflow output is too large")
            # Flush every local write before the final fence. No action may commit
            # independently; an expired lease rolls back all effects and audits.
            db.flush()
            now = clock(db)
            assert step.lease_until is not None
            if now >= step.lease_until or now >= run.deadline_at:
                raise TransientActionError()
            db.add(
                PlaybookEffect(
                    step_id=step.id, output=output, output_sha256=digest(output), created_at=now
                )
            )
            attempt(db, step, now, "completed", None)
            step.state, step.finished_at, step.lease_until = "completed", now, None
            db.flush()
            pending = db.scalar(
                select(PlaybookStep.id)
                .where(PlaybookStep.run_id == run.id, PlaybookStep.state != "completed")
                .limit(1)
            )
            run.next_attempt_at = now
            if pending is None:
                run.state, run.finished_at = "completed", now
                audit(db, "run_completed", run.id, actor.id, {}, str(run.id))
            audit(
                db,
                "step_completed",
                run.id,
                actor.id,
                {"step": step.step_id, "attempt": step.attempts, "output_sha256": digest(output)},
                str(run.id),
            )
            db.commit()
            return True
    except (TransientActionError, OperationalError):
        record_failure(database, claim, "soar_temporary_failure", retryable=True)
    except (ApiError, ValueError, TypeError, KeyError) as error:
        record_failure(
            database,
            claim,
            error.code if isinstance(error, ApiError) else "soar_context_integrity",
            retryable=False,
        )
    return False


def process_once(database: Database) -> bool:
    claim = claim_next(database)
    return execute_claim(database, claim) if claim is not None else False
