"""Authenticated case reads and audited, optimistic incident management."""

import hashlib
import re
from typing import Annotated, Any, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from sqlalchemy import func, select, tuple_

from app.api.dependencies import DB, Principal, lock_authority, require
from app.core.cursors import CursorCodec
from app.core.errors import ApiError
from app.core.permissions import Permission, has_permission
from app.core.rate_limit import rate_limit
from app.modules.alerts.models import Alert
from app.modules.incidents import service, views
from app.modules.incidents.models import (
    Incident,
    IncidentAlert,
    IncidentCreateReceipt,
    IncidentNote,
    IncidentTimeline,
)
from app.modules.incidents.schemas import (
    Actor,
    AlertAttach,
    EvidenceView,
    IncidentCreate,
    IncidentDetail,
    IncidentFilters,
    IncidentPatch,
    IncidentSummary,
    NoteCreate,
    NoteView,
    Page,
    PageFilters,
    TimelineView,
)
from app.modules.ingestion.schemas import canonical_json
from app.modules.users.models import User

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])
Reader = Annotated[Principal, Depends(require(Permission.INCIDENTS_READ))]
Editor = Annotated[Principal, Depends(require(Permission.INCIDENTS_EDIT))]


def _headers(response: Response, incident: Incident | None = None) -> None:
    response.headers["Cache-Control"] = "no-store"
    if incident is not None:
        response.headers["ETag"] = f'"{incident.version}"'


def _codec(data: PageFilters, request: Request, principal: Principal, path: str) -> CursorCodec:
    scope = data.model_dump(mode="json", exclude={"cursor"})
    scope.update({"user_id": str(principal.user.id), "path": path})
    return CursorCodec(
        request.app.state.settings.jwt_secret.get_secret_value(), "aegis-incident-cursor-v1", scope
    )


def _read(db: DB, identifier: UUID) -> Incident:
    incident = db.get(Incident, identifier)
    if incident is None:
        raise ApiError(404, "incident_not_found", "Incident not found")
    return incident


def _locked(
    db: DB, identifier: UUID, version: str | None, principal: Principal, request: Request
) -> Incident:
    if version is None:
        raise ApiError(428, "version_required", "If-Match is required")
    lock_authority(db, principal, Permission.INCIDENTS_EDIT, request)
    incident = db.scalar(
        select(Incident)
        .where(Incident.id == identifier)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if incident is None:
        raise ApiError(404, "incident_not_found", "Incident not found")
    if version != f'"{incident.version}"':
        raise ApiError(412, "version_conflict", "Refresh the incident before updating")
    return incident


def _finish(db: DB, response: Response, incident: Incident) -> IncidentDetail:
    db.commit()
    _headers(response, incident)
    return views.detail(db, incident)


@router.get("", response_model=Page[IncidentSummary])
def list_incidents(
    data: Annotated[IncidentFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> Page[IncidentSummary]:
    rate_limit(request, "incident-list", str(principal.user.id), 60, window_seconds=60)
    codec = _codec(data, request, principal, "incidents")
    anchor, after = codec.read(data.cursor)
    filters: list[Any] = [Incident.created_at <= anchor]
    for name in ("status", "severity", "mode", "owner_id", "run_id"):
        value = getattr(data, name)
        if value is not None:
            filters.append(getattr(Incident, name) == value)
    if data.dataset_id is not None:
        filters.append(
            Incident.dataset_ids.contains([str(data.dataset_id)])
            | (Incident.dataset_id == data.dataset_id)
        )
    if data.tag is not None:
        filters.append(Incident.tags.contains([data.tag.strip().casefold()]))
    total = int(db.scalar(select(func.count()).select_from(Incident).where(*filters)) or 0)
    query = (
        select(Incident)
        .where(*filters)
        .order_by(Incident.created_at.desc(), Incident.id.desc())
        .limit(data.limit + 1)
    )
    if after is not None:
        query = query.where(tuple_(Incident.created_at, Incident.id) < after)
    rows = list(db.scalars(query))
    next_cursor = (
        codec.next(anchor, rows[data.limit - 1].created_at, rows[data.limit - 1].id)
        if len(rows) > data.limit
        else None
    )
    _headers(response)
    return Page(
        items=[views.summary(db, row) for row in rows[: data.limit]],
        total=total,
        next_cursor=next_cursor,
    )


@router.get("/assignees")
def assignees(response: Response, db: DB, principal: Editor) -> dict[str, list[Actor]]:
    query = (
        select(User)
        .where(User.enabled.is_(True), User.role.in_(service.OWNER_ROLES))
        .order_by(User.username, User.id)
        .limit(100)
    )
    if not has_permission(principal.user.role, Permission.INCIDENTS_ASSIGN_ANY):
        query = query.where(User.id == principal.user.id)
    _headers(response)
    return {"items": [Actor.model_validate(user) for user in db.scalars(query)]}


@router.post("", status_code=201, response_model=IncidentDetail)
def create_incident(
    data: IncidentCreate,
    request: Request,
    response: Response,
    db: DB,
    principal: Editor,
    idempotency_key: Annotated[str | None, Header()] = None,
) -> IncidentDetail:
    if idempotency_key is None:
        raise ApiError(428, "idempotency_required", "Idempotency-Key is required")
    if re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", idempotency_key) is None:
        raise ApiError(422, "invalid_idempotency_key", "Idempotency-Key is invalid")
    lock_authority(db, principal, Permission.INCIDENTS_EDIT, request)
    body_hash = hashlib.sha256(canonical_json(data.model_dump(mode="json"))).hexdigest()
    receipt = db.get(IncidentCreateReceipt, (principal.user.id, idempotency_key))
    if receipt is not None:
        if receipt.body_sha256 != body_hash:
            raise ApiError(
                409, "idempotency_conflict", "Idempotency-Key was used with a different request"
            )
        incident = _read(db, receipt.incident_id)
        response.status_code = 200
        _headers(response, incident)
        return views.detail(db, incident)
    incident = service.create_incident(
        db, data, request_id=request.state.request_id, actor=principal.user
    )
    db.add(
        IncidentCreateReceipt(
            actor_id=principal.user.id,
            key=idempotency_key,
            body_sha256=body_hash,
            incident_id=incident.id,
        )
    )
    return _finish(db, response, incident)


@router.get("/{incident_id}", response_model=IncidentDetail)
def incident_detail(
    incident_id: UUID, response: Response, db: DB, principal: Reader
) -> IncidentDetail:
    incident = _read(db, incident_id)
    _headers(response, incident)
    return views.detail(db, incident)


@router.patch("/{incident_id}", response_model=IncidentDetail)
def update_incident(
    incident_id: UUID,
    data: IncidentPatch,
    request: Request,
    response: Response,
    db: DB,
    principal: Editor,
    if_match: Annotated[str | None, Header()] = None,
) -> IncidentDetail:
    incident = _locked(db, incident_id, if_match, principal, request)
    service.patch_incident(
        db, incident, data, request_id=request.state.request_id, actor=principal.user
    )
    return _finish(db, response, incident)


@router.post("/{incident_id}/alerts", response_model=IncidentDetail)
def attach_alert(
    incident_id: UUID,
    data: AlertAttach,
    request: Request,
    response: Response,
    db: DB,
    principal: Editor,
    if_match: Annotated[str | None, Header()] = None,
) -> IncidentDetail:
    incident = _locked(db, incident_id, if_match, principal, request)
    alert = db.get(Alert, data.alert_id)
    if alert is None:
        raise ApiError(404, "alert_not_found", "Alert not found")
    service.attach_alert(
        db, incident, alert, request_id=request.state.request_id, actor=principal.user
    )
    return _finish(db, response, incident)


@router.delete("/{incident_id}/alerts/{alert_id}", response_model=IncidentDetail)
def detach_alert(
    incident_id: UUID,
    alert_id: UUID,
    request: Request,
    response: Response,
    db: DB,
    principal: Editor,
    if_match: Annotated[str | None, Header()] = None,
) -> IncidentDetail:
    incident = _locked(db, incident_id, if_match, principal, request)
    service.detach_alert(
        db, incident, alert_id, request_id=request.state.request_id, actor=principal.user
    )
    return _finish(db, response, incident)


@router.post("/{incident_id}/notes", response_model=IncidentDetail)
def add_note(
    incident_id: UUID,
    data: NoteCreate,
    request: Request,
    response: Response,
    db: DB,
    principal: Editor,
    if_match: Annotated[str | None, Header()] = None,
) -> IncidentDetail:
    incident = _locked(db, incident_id, if_match, principal, request)
    service.add_note(
        db, incident, data.body, request_id=request.state.request_id, actor=principal.user
    )
    return _finish(db, response, incident)


@router.get("/{incident_id}/timeline", response_model=Page[TimelineView])
@router.get("/{incident_id}/notes", response_model=Page[NoteView])
@router.get("/{incident_id}/evidence", response_model=Page[EvidenceView])
def incident_collection(
    incident_id: UUID,
    data: Annotated[PageFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> Page[Any]:
    _read(db, incident_id)
    collection = request.url.path.rsplit("/", 1)[-1]
    codec = _codec(data, request, principal, f"{incident_id}/{collection}")
    anchor, after = codec.read(data.cursor)
    models: dict[str, type[IncidentTimeline] | type[IncidentNote] | type[IncidentAlert]] = {
        "timeline": IncidentTimeline,
        "notes": IncidentNote,
        "evidence": IncidentAlert,
    }
    model = models[collection]
    moment = {
        "timeline": IncidentTimeline.occurred_at,
        "notes": IncidentNote.created_at,
        "evidence": IncidentAlert.linked_at,
    }[collection]
    filters = [model.incident_id == incident_id, moment <= anchor]
    total = int(db.scalar(select(func.count()).select_from(model).where(*filters)) or 0)
    query = (
        select(model).where(*filters).order_by(moment.desc(), model.id.desc()).limit(data.limit + 1)
    )
    if after is not None:
        query = query.where(tuple_(moment, model.id) < after)
    rows = cast(list[IncidentTimeline | IncidentNote | IncidentAlert], list(db.scalars(query)))
    timestamp_key = {"timeline": "occurred_at", "notes": "created_at", "evidence": "linked_at"}[
        collection
    ]
    next_cursor = (
        codec.next(anchor, getattr(rows[data.limit - 1], timestamp_key), rows[data.limit - 1].id)
        if len(rows) > data.limit
        else None
    )
    items: list[Any] = []
    for row in rows[: data.limit]:
        if isinstance(row, IncidentAlert):
            alert = db.get(Alert, row.alert_id)
            assert alert is not None
            items.append(views.evidence(row, alert))
        elif isinstance(row, IncidentNote):
            items.append(NoteView.model_validate(row))
        else:
            items.append(TimelineView.model_validate(row))
    _headers(response)
    return Page(items=items, total=total, next_cursor=next_cursor)
