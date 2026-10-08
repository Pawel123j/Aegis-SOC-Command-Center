"""Bounded, integrity-checked workflow history, never Celery result state."""

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.modules.soar.models import (
    Playbook,
    PlaybookAttempt,
    PlaybookEffect,
    PlaybookRevision,
    PlaybookRun,
    PlaybookStep,
)
from app.modules.soar.schemas import digest, required_permissions
from app.modules.soar.service import TERMINAL, revision, verified_revision


def book_view(db: Session, book: Playbook) -> dict[str, Any]:
    latest = revision(db, book, book.latest_revision)
    published = revision(db, book, book.published_revision) if book.published_revision else None
    return {
        "id": book.id,
        "version": book.version,
        "enabled": book.enabled,
        "latest_revision": book.latest_revision,
        "published_revision": book.published_revision,
        "definition": latest.document,
        "published_definition": published.document if published else None,
        "published_sha256": published.document_sha256 if published else None,
        "created_at": book.created_at,
        "created_by": book.created_by,
        "required_permissions": sorted(
            required_permissions(verified_revision(published or latest))
        ),
    }


def run_summary(row: PlaybookRun) -> dict[str, Any]:
    return {
        key: getattr(row, key)
        for key in (
            "id",
            "revision_id",
            "alert_id",
            "requested_by",
            "execution_mode",
            "mode",
            "dataset_id",
            "data_run_id",
            "state",
            "cancellation_requested",
            "error_code",
            "created_at",
            "started_at",
            "finished_at",
            "deadline_at",
            "next_attempt_at",
            "replay_of",
        )
    }


def run_view(db: Session, row: PlaybookRun) -> dict[str, Any]:
    frozen = db.get(PlaybookRevision, row.revision_id)
    if frozen is None or digest(row.context) != row.context_sha256:
        raise ApiError(409, "soar_context_integrity", "Workflow proof is invalid")
    definition = verified_revision(frozen)
    steps = list(
        db.scalars(
            select(PlaybookStep)
            .where(PlaybookStep.run_id == row.id)
            .order_by(PlaybookStep.position)
        )
    )
    if len(steps) != len(definition.steps):
        raise ApiError(409, "soar_steps_integrity", "Workflow steps are invalid")
    items = []
    for step in steps:
        effect = db.get(PlaybookEffect, step.id)
        if effect is not None and digest(effect.output) != effect.output_sha256:
            raise ApiError(409, "soar_effect_integrity", "Workflow output is invalid")
        attempts = list(
            db.scalars(
                select(PlaybookAttempt)
                .where(PlaybookAttempt.step_id == step.id)
                .order_by(PlaybookAttempt.number)
            )
        )
        items.append(
            {
                "id": step.step_id,
                "position": step.position,
                "action": step.action,
                "state": step.state,
                "attempts": step.attempts,
                "input_sha256": step.input_sha256,
                "started_at": step.started_at,
                "finished_at": step.finished_at,
                "lease_until": step.lease_until,
                "error_code": step.error_code,
                "not_executed_reason": f"run_{row.state}"
                if row.state in TERMINAL and step.state == "waiting"
                else None,
                "output": effect.output if effect else None,
                "output_sha256": effect.output_sha256 if effect else None,
                "history": [
                    {
                        key: getattr(attempt, key)
                        for key in ("number", "started_at", "finished_at", "outcome", "error_code")
                    }
                    for attempt in attempts
                ],
            }
        )
    return {
        **run_summary(row),
        "playbook_id": frozen.playbook_id,
        "revision": frozen.revision,
        "definition": frozen.document,
        "document_sha256": frozen.document_sha256,
        "context": row.context,
        "context_sha256": row.context_sha256,
        "steps": items,
    }
