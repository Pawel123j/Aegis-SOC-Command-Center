"""Definition publication and actor-bound, idempotent queue admission."""

from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.core.permissions import has_permission
from app.infrastructure.database import utcnow
from app.modules.audit.service import append_audit
from app.modules.ingestion.schemas import canonical_json
from app.modules.soar.evidence import alert_record, capture_context
from app.modules.soar.models import Playbook, PlaybookRevision, PlaybookRun, PlaybookStep
from app.modules.soar.schemas import (
    ENGINE_VERSION,
    MAX_ACTIVE_RUNS,
    MAX_PLAYBOOKS,
    MAX_REVISIONS,
    Definition,
    RunInput,
    digest,
    required_permissions,
)
from app.modules.users.models import User

TERMINAL = frozenset({"completed", "failed", "cancelled"})


def audit(
    db: Session,
    action: str,
    identifier: UUID,
    actor: UUID,
    details: dict[str, Any],
    request_id: str,
) -> None:
    append_audit(
        db,
        action=f"soar.{action}",
        outcome="success",
        request_id=request_id,
        actor_id=actor,
        object_type="playbook",
        object_id=str(identifier),
        details=details,
    )


def record(db: Session, identifier: UUID, *, locked: bool = False) -> Playbook:
    statement = select(Playbook).where(Playbook.id == identifier)
    if locked:
        statement = statement.with_for_update().execution_options(populate_existing=True)
    row = db.scalar(statement)
    if row is None:
        raise ApiError(404, "playbook_not_found", "Playbook not found")
    return row


def revision(db: Session, book: Playbook, number: int) -> PlaybookRevision:
    row = db.scalar(
        select(PlaybookRevision).where(
            PlaybookRevision.playbook_id == book.id, PlaybookRevision.revision == number
        )
    )
    if row is None:
        raise ApiError(404, "playbook_revision_not_found", "Playbook revision not found")
    verified_revision(row)
    return row


def verified_revision(row: PlaybookRevision) -> Definition:
    try:
        definition = Definition.model_validate(row.document)
        if (
            row.engine_version != ENGINE_VERSION
            or definition.model_dump(mode="json") != row.document
            or canonical_json(row.document).decode() != row.canonical_document
            or digest(row.document) != row.document_sha256
        ):
            raise ValueError("revision proof mismatch")
        return definition
    except (ValueError, TypeError, KeyError):
        raise ApiError(409, "soar_revision_integrity", "Playbook revision is invalid") from None


def add_revision(
    db: Session, book: Playbook, data: Definition, actor: User, request_id: str
) -> PlaybookRevision:
    document = data.model_dump(mode="json")
    row = PlaybookRevision(
        playbook_id=book.id,
        revision=book.latest_revision,
        document=document,
        canonical_document=canonical_json(document).decode(),
        document_sha256=digest(document),
        engine_version=ENGINE_VERSION,
        created_by=actor.id,
    )
    db.add(row)
    db.flush()
    audit(
        db,
        "revision_created",
        book.id,
        actor.id,
        {"revision": row.revision, "document_sha256": row.document_sha256},
        request_id,
    )
    return row


def create_book(db: Session, data: Definition, actor: User, request_id: str) -> Playbook:
    if int(db.scalar(select(func.count()).select_from(Playbook)) or 0) >= MAX_PLAYBOOKS:
        raise ApiError(409, "soar_catalog_limit", "Playbook catalog limit reached")
    book = Playbook(created_by=actor.id)
    db.add(book)
    db.flush()
    add_revision(db, book, data, actor, request_id)
    return book


def change_revision(
    db: Session, book: Playbook, data: Definition, actor: User, request_id: str
) -> None:
    if book.latest_revision >= MAX_REVISIONS:
        raise ApiError(409, "soar_revision_limit", "Playbook revision limit reached")
    if revision(db, book, book.latest_revision).document == data.model_dump(mode="json"):
        raise ApiError(409, "soar_unchanged", "Playbook definition is unchanged")
    book.latest_revision += 1
    add_revision(db, book, data, actor, request_id)


def authorize_actions(actor: User, definition: Definition) -> None:
    if not actor.enabled or any(
        not has_permission(actor.role, p) for p in required_permissions(definition)
    ):
        raise ApiError(403, "soar_authority_revoked", "Workflow action permission denied")


def start_run(
    db: Session, book: Playbook, data: RunInput, key: str, actor: User, request_id: str
) -> tuple[PlaybookRun, bool]:
    request_hash = digest({"playbook_id": str(book.id), **data.model_dump(mode="json")})
    old = db.scalar(
        select(PlaybookRun).where(
            PlaybookRun.requested_by == actor.id, PlaybookRun.idempotency_key == key
        )
    )
    if old is not None:
        if old.request_sha256 != request_hash:
            raise ApiError(
                409, "idempotency_conflict", "Idempotency key belongs to another request"
            )
        return old, False
    if not book.enabled or book.published_revision != data.revision:
        raise ApiError(
            409, "soar_not_published", "Refresh and choose the current published revision"
        )
    frozen = revision(db, book, data.revision)
    definition = verified_revision(frozen)
    authorize_actions(actor, definition)
    alert = alert_record(db, data.alert_id)
    if alert.status == "false_positive":
        raise ApiError(
            409, "soar_false_positive", "Review false-positive disposition before starting"
        )
    if data.replay_of is not None:
        original = db.get(PlaybookRun, data.replay_of)
        if (
            original is None
            or original.state not in {"failed", "cancelled"}
            or original.alert_id != alert.id
            or original.revision_id != frozen.id
        ):
            raise ApiError(
                409,
                "soar_replay_invalid",
                "Replay must reference a stopped run of this version and alert",
            )
    active = db.scalar(
        select(func.count()).select_from(PlaybookRun).where(PlaybookRun.state.not_in(TERMINAL))
    )
    if int(active or 0) >= MAX_ACTIVE_RUNS:
        raise ApiError(409, "soar_queue_full", "Workflow queue capacity reached")
    context = capture_context(db, alert, data)
    if data.replay_of is not None:
        assert original is not None
        if any(context[key] != original.context[key] for key in ("event_id", "ip_field")):
            raise ApiError(409, "soar_replay_invalid", "Replay must preserve its original target")
    now = utcnow()
    run = PlaybookRun(
        id=uuid4(),
        revision_id=frozen.id,
        alert_id=alert.id,
        requested_by=actor.id,
        idempotency_key=key,
        request_sha256=request_hash,
        replay_of=data.replay_of,
        mode=alert.mode,
        dataset_id=alert.dataset_id,
        data_run_id=alert.run_id,
        context=context,
        context_sha256=digest(context),
        deadline_at=now + timedelta(minutes=10),
        created_at=now,
        next_attempt_at=now,
    )
    db.add(run)
    db.flush()
    for position, item in enumerate(definition.steps):
        db.add(
            PlaybookStep(
                run_id=run.id,
                position=position,
                step_id=item.id,
                action=item.action,
                input_sha256=digest(
                    {
                        "context": run.context_sha256,
                        "step": item.model_dump(),
                        "engine": ENGINE_VERSION,
                    }
                ),
            )
        )
    audit(
        db,
        "run_queued",
        run.id,
        actor.id,
        {
            "revision_id": str(frozen.id),
            "alert_id": str(alert.id),
            "execution_mode": "simulation",
            "context_sha256": run.context_sha256,
            "replay_of": str(data.replay_of) if data.replay_of else None,
        },
        request_id,
    )
    db.flush()
    return run, True
