"""Server-authorized playbook publication, simulation-only runs and local inbox."""

import re
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from sqlalchemy import select

from app.api.dependencies import DB, Principal, lock_authority, require
from app.core.errors import ApiError
from app.core.permissions import Permission, has_permission
from app.core.rate_limit import rate_limit
from app.modules.ingestion.models import LIVE_RUN_ID
from app.modules.soar.evidence import alert_record, event_targets, target_view
from app.modules.soar.models import Playbook, PlaybookRun, PlaybookStep, SoarNotification
from app.modules.soar.processing import clock, stop_run
from app.modules.soar.schemas import Availability, Definition, Publication, RunInput, catalog
from app.modules.soar.service import (
    TERMINAL,
    audit,
    change_revision,
    create_book,
    record,
    revision,
    start_run,
)
from app.modules.soar.views import book_view, run_summary, run_view

router = APIRouter(prefix="/api/v1", tags=["soar"])
Reader = Annotated[Principal, Depends(require(Permission.PLAYBOOKS_READ))]
Manager = Annotated[Principal, Depends(require(Permission.PLAYBOOKS_MANAGE))]
Runner = Annotated[Principal, Depends(require(Permission.PLAYBOOKS_RUN))]


def read_access(principal: Principal, request: Request, response: Response) -> None:
    if any(
        not has_permission(principal.user.role, p)
        for p in (
            Permission.EVENTS_READ,
            Permission.ALERTS_READ,
            Permission.INCIDENTS_READ,
            Permission.INTELLIGENCE_READ,
        )
    ):
        raise ApiError(403, "forbidden", "Permission denied")
    rate_limit(request, "soar-read", str(principal.user.id), 120, window_seconds=60)
    response.headers["Cache-Control"] = "no-store"


def mutation(db: DB, principal: Principal, request: Request, permission: Permission) -> None:
    rate_limit(request, "soar-write", str(principal.user.id), 30, window_seconds=60)
    lock_authority(db, principal, permission, request)


def etag(book: Playbook, response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["ETag"] = f'"{book.version}"'


def match(book: Playbook, value: str | None) -> None:
    if value is None:
        raise ApiError(428, "version_required", "If-Match is required")
    if value != f'"{book.version}"':
        raise ApiError(412, "version_conflict", "Refresh the playbook before changing it")


def run_record(db: DB, identifier: UUID, *, locked: bool = False) -> PlaybookRun:
    statement = select(PlaybookRun).where(PlaybookRun.id == identifier)
    if locked:
        statement = statement.with_for_update().execution_options(populate_existing=True)
    row = db.scalar(statement)
    if row is None:
        raise ApiError(404, "playbook_run_not_found", "Playbook run not found")
    return row


@router.get("/playbooks/actions")
def actions(response: Response, request: Request, principal: Reader) -> dict[str, Any]:
    read_access(principal, request, response)
    return catalog()


@router.get("/playbook-targets/{alert_id}")
def targets(
    alert_id: UUID, request: Request, response: Response, db: DB, principal: Reader
) -> dict[str, Any]:
    read_access(principal, request, response)
    alert = alert_record(db, alert_id)
    return {
        "alert_id": alert.id,
        "title": alert.title,
        "anchor_event_id": alert.event_id,
        "mode": alert.mode,
        "dataset_id": alert.dataset_id,
        "data_run_id": alert.run_id,
        "items": [target_view(event) for event in event_targets(alert)],
    }


@router.get("/playbooks")
def list_books(request: Request, response: Response, db: DB, principal: Reader) -> dict[str, Any]:
    read_access(principal, request, response)
    books = db.scalars(
        select(Playbook).order_by(Playbook.created_at.desc(), Playbook.id).limit(100)
    )
    return {"items": [book_view(db, book) for book in books]}


@router.get("/playbooks/{playbook_id}")
def get_book(
    playbook_id: UUID, request: Request, response: Response, db: DB, principal: Reader
) -> dict[str, Any]:
    read_access(principal, request, response)
    book = record(db, playbook_id)
    etag(book, response)
    return book_view(db, book)


@router.post("/playbooks", status_code=201)
def create(
    data: Definition, request: Request, response: Response, db: DB, principal: Manager
) -> dict[str, Any]:
    mutation(db, principal, request, Permission.PLAYBOOKS_MANAGE)
    book = create_book(db, data, principal.user, request.state.request_id)
    db.commit()
    etag(book, response)
    return book_view(db, book)


@router.post("/playbooks/{playbook_id}/versions", status_code=201)
def new_version(
    playbook_id: UUID,
    data: Definition,
    request: Request,
    response: Response,
    db: DB,
    principal: Manager,
    if_match: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    mutation(db, principal, request, Permission.PLAYBOOKS_MANAGE)
    book = record(db, playbook_id, locked=True)
    match(book, if_match)
    change_revision(db, book, data, principal.user, request.state.request_id)
    db.commit()
    etag(book, response)
    return book_view(db, book)


@router.post("/playbooks/{playbook_id}/publish")
def publish(
    playbook_id: UUID,
    data: Publication,
    request: Request,
    response: Response,
    db: DB,
    principal: Manager,
    if_match: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    mutation(db, principal, request, Permission.PLAYBOOKS_MANAGE)
    book = record(db, playbook_id, locked=True)
    match(book, if_match)
    if data.revision != book.latest_revision:
        raise ApiError(409, "soar_revision_conflict", "Only the latest revision can be published")
    row = revision(db, book, data.revision)
    book.published_revision = data.revision
    audit(
        db,
        "published",
        book.id,
        principal.user.id,
        {"revision": row.revision, "document_sha256": row.document_sha256},
        request.state.request_id,
    )
    db.commit()
    etag(book, response)
    return book_view(db, book)


@router.patch("/playbooks/{playbook_id}")
def availability(
    playbook_id: UUID,
    data: Availability,
    request: Request,
    response: Response,
    db: DB,
    principal: Manager,
    if_match: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    mutation(db, principal, request, Permission.PLAYBOOKS_MANAGE)
    book = record(db, playbook_id, locked=True)
    match(book, if_match)
    book.enabled = data.enabled
    audit(
        db,
        "availability_changed",
        book.id,
        principal.user.id,
        {"enabled": data.enabled},
        request.state.request_id,
    )
    db.commit()
    etag(book, response)
    return book_view(db, book)


@router.post("/playbooks/{playbook_id}/runs", status_code=201)
def run(
    playbook_id: UUID,
    data: RunInput,
    request: Request,
    response: Response,
    db: DB,
    principal: Runner,
    idempotency_key: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    if idempotency_key is None or re.fullmatch(r"[A-Za-z0-9_-]{16,128}", idempotency_key) is None:
        raise ApiError(422, "idempotency_key_required", "A bounded Idempotency-Key is required")
    mutation(db, principal, request, Permission.PLAYBOOKS_RUN)
    read_access(principal, request, response)
    book = record(db, playbook_id, locked=True)
    row, created = start_run(
        db, book, data, idempotency_key, principal.user, request.state.request_id
    )
    db.commit()
    if not created:
        response.status_code = 200
    return run_view(db, row)


@router.get("/playbook-runs")
def list_runs(
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
    mode: Literal["live", "replay"] = "live",
    dataset_id: UUID | None = None,
    data_run_id: UUID | None = None,
    alert_id: UUID | None = None,
    before: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> dict[str, Any]:
    read_access(principal, request, response)
    if (mode == "live" and (dataset_id is not None or data_run_id not in (None, LIVE_RUN_ID))) or (
        mode == "replay" and (dataset_id is None or data_run_id in (None, LIVE_RUN_ID))
    ):
        raise ApiError(422, "soar_scope_invalid", "Select an exact live or replay scope")
    statement = select(PlaybookRun).where(PlaybookRun.mode == mode)
    if mode == "replay":
        statement = statement.where(
            PlaybookRun.dataset_id == dataset_id, PlaybookRun.data_run_id == data_run_id
        )
    if alert_id is not None:
        statement = statement.where(PlaybookRun.alert_id == alert_id)
    if before is not None:
        anchor = run_record(db, before)
        if (
            anchor.mode != mode
            or (
                mode == "replay"
                and (anchor.dataset_id != dataset_id or anchor.data_run_id != data_run_id)
            )
            or (alert_id is not None and anchor.alert_id != alert_id)
        ):
            raise ApiError(422, "soar_scope_invalid", "Cursor scope mismatch")
        from sqlalchemy import tuple_

        statement = statement.where(
            tuple_(PlaybookRun.created_at, PlaybookRun.id) < (anchor.created_at, anchor.id)
        )
    rows = list(
        db.scalars(
            statement.order_by(PlaybookRun.created_at.desc(), PlaybookRun.id.desc()).limit(
                limit + 1
            )
        )
    )
    return {
        "items": [run_summary(row) for row in rows[:limit]],
        "next_cursor": str(rows[limit - 1].id) if len(rows) > limit else None,
    }


@router.get("/playbook-runs/{run_id}")
def get_run(
    run_id: UUID, request: Request, response: Response, db: DB, principal: Reader
) -> dict[str, Any]:
    read_access(principal, request, response)
    # Locking the run gives detail and step history a coherent snapshot while
    # workers serialize the same row. No state is changed by this read.
    return run_view(db, run_record(db, run_id, locked=True))


@router.post("/playbook-runs/{run_id}/cancel")
def cancel(
    run_id: UUID, request: Request, response: Response, db: DB, principal: Runner
) -> dict[str, Any]:
    mutation(db, principal, request, Permission.PLAYBOOKS_RUN)
    read_access(principal, request, response)
    row = run_record(db, run_id, locked=True)
    if row.requested_by != principal.user.id and not has_permission(
        principal.user.role, Permission.PLAYBOOKS_MANAGE
    ):
        raise ApiError(403, "forbidden", "Only the initiator or a manager may cancel")
    if row.state == "cancelled":
        return run_view(db, row)
    if row.state in TERMINAL:
        raise ApiError(409, "soar_terminal", "Completed history cannot be cancelled")
    row.cancellation_requested = True
    stop_run(db, row, clock(db), "soar_cancelled", cancelled=True)
    audit(db, "cancel_requested", row.id, principal.user.id, {}, request.state.request_id)
    db.commit()
    return run_view(db, row)


@router.get("/soar-notifications")
def notifications(
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
    before: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> dict[str, Any]:
    read_access(principal, request, response)
    statement = (
        select(SoarNotification, PlaybookStep.run_id)
        .join(PlaybookStep, PlaybookStep.id == SoarNotification.step_id)
        .where(SoarNotification.recipient_id == principal.user.id)
    )
    if before is not None:
        anchor = db.get(SoarNotification, before)
        if anchor is None or anchor.recipient_id != principal.user.id:
            raise ApiError(404, "notification_not_found", "Notification not found")
        from sqlalchemy import tuple_

        statement = statement.where(
            tuple_(SoarNotification.created_at, SoarNotification.id)
            < (anchor.created_at, anchor.id)
        )
    rows = db.execute(
        statement.order_by(SoarNotification.created_at.desc(), SoarNotification.id.desc()).limit(
            limit + 1
        )
    ).all()
    return {
        "items": [
            {
                "id": row.id,
                "run_id": run_id,
                "created_at": row.created_at,
                "read_at": row.read_at,
                "message": row.message,
            }
            for row, run_id in rows[:limit]
        ],
        "next_cursor": str(rows[limit - 1][0].id) if len(rows) > limit else None,
    }


@router.post("/soar-notifications/{notification_id}/read")
def mark_read(
    notification_id: UUID, request: Request, response: Response, db: DB, principal: Reader
) -> dict[str, Any]:
    mutation(db, principal, request, Permission.PLAYBOOKS_READ)
    read_access(principal, request, response)
    row = db.get(SoarNotification, notification_id)
    if row is None or row.recipient_id != principal.user.id:
        raise ApiError(404, "notification_not_found", "Notification not found")
    if row.read_at is None:
        row.read_at = clock(db)
        audit(db, "notification_read", row.id, principal.user.id, {}, request.state.request_id)
        db.commit()
    return {"id": row.id, "read_at": row.read_at}
