"""Scope-explicit evidence profiles and explicit administrator indexing of historical data."""

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response

from app.api.dependencies import DB, Principal, lock_authority, require
from app.core.cursors import CursorCodec
from app.core.errors import ApiError
from app.core.permissions import Permission, has_permission
from app.core.rate_limit import rate_limit
from app.modules.entities import indexing, queries, views
from app.modules.entities.schemas import (
    BackfillInput,
    BackfillResult,
    EntityAlert,
    EntityDetail,
    EntityFilters,
    EntityIncident,
    EntityPage,
    EntitySummary,
    EventActivity,
)

router = APIRouter(prefix="/api/v1/entities", tags=["entities"])
Reader = Annotated[Principal, Depends(require(Permission.EVENTS_READ))]
Administrator = Annotated[Principal, Depends(require(Permission.SYSTEM_MANAGE))]


def _prepare(
    filters: EntityFilters, principal: Principal, request: Request, response: Response, path: str
) -> CursorCodec:
    if not all(
        has_permission(principal.user.role, permission)
        for permission in (
            Permission.EVENTS_READ,
            Permission.ALERTS_READ,
            Permission.INCIDENTS_READ,
        )
    ):
        raise ApiError(403, "forbidden", "Permission denied")
    rate_limit(request, "entity-reads", str(principal.user.id), 120, window_seconds=60)
    response.headers["Cache-Control"] = "no-store"
    query = filters.model_dump(mode="json", exclude={"cursor"})
    query.update({"user_id": str(principal.user.id), "path": path})
    return CursorCodec(
        request.app.state.settings.jwt_secret.get_secret_value(), "aegis-entity-cursor-v1", query
    )


def _profiles(
    filters: EntityFilters,
    principal: Principal,
    request: Request,
    response: Response,
    db: DB,
    *,
    identifier: UUID | None = None,
    event_id: UUID | None = None,
    related_id: UUID | None = None,
) -> Any:
    codec = _prepare(filters, principal, request, response, str(request.url.path))
    anchor, after = codec.read(filters.cursor)
    params = queries.parameters(
        filters, anchor, after, identifier=identifier, event_id=event_id, related_id=related_id
    )
    raw = queries.profiles(db, params)
    scoped = views.scope(filters, params)
    status = views.status(raw["index_status"])
    if event_id is not None and not raw["event_found"]:
        raise ApiError(404, "event_not_found", "Event not found in this activity scope")
    if related_id is not None and not raw["related_found"]:
        raise ApiError(404, "entity_not_found", "Entity not found in this activity scope")
    if identifier is not None:
        if not raw["items"]:
            raise ApiError(404, "entity_not_found", "Entity not found in this activity scope")
        return views.detail(raw["items"][0], scoped, status)
    rows = raw["items"][: filters.limit]
    next_cursor = None
    if len(raw["items"]) > filters.limit:
        identity = rows[-1]["identity"]
        next_cursor = codec.next(
            anchor, views._timestamp(identity["created_at"]), UUID(identity["id"])
        )
    return EntityPage[EntitySummary](
        scope=scoped,
        items=[views.summary(item) for item in rows],
        total=raw["total"],
        next_cursor=next_cursor,
        index_status=status,
    )


@router.get("", response_model=EntityPage[EntitySummary])
def entities(
    filters: Annotated[EntityFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> Any:
    return _profiles(filters, principal, request, response, db)


@router.get("/by-event/{event_id}", response_model=EntityPage[EntitySummary])
def by_event(
    event_id: UUID,
    filters: Annotated[EntityFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> Any:
    return _profiles(filters, principal, request, response, db, event_id=event_id)


@router.post("/backfill", response_model=BackfillResult)
def backfill(
    data: BackfillInput, request: Request, response: Response, db: DB, principal: Administrator
) -> BackfillResult:
    rate_limit(request, "entity-backfill", str(principal.user.id), 30, window_seconds=60)
    lock_authority(db, principal, Permission.SYSTEM_MANAGE, request)
    result = indexing.backfill(
        db, data.limit, actor_id=principal.user.id, request_id=request.state.request_id
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return result


@router.get("/{entity_id}", response_model=EntityDetail)
def detail(
    entity_id: UUID,
    filters: Annotated[EntityFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> Any:
    return _profiles(filters, principal, request, response, db, identifier=entity_id)


@router.get("/{entity_id}/related", response_model=EntityPage[EntitySummary])
def related(
    entity_id: UUID,
    filters: Annotated[EntityFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> Any:
    if filters.kind is None:
        filters = filters.model_copy(update={"kind": "host"})
    return _profiles(filters, principal, request, response, db, related_id=entity_id)


def _collection(
    kind: Literal["events", "alerts", "incidents"],
    entity_id: UUID,
    filters: EntityFilters,
    request: Request,
    response: Response,
    db: DB,
    principal: Principal,
) -> Any:
    codec = _prepare(filters, principal, request, response, str(request.url.path))
    anchor, after = codec.read(filters.cursor)
    params = queries.parameters(filters, anchor, None, identifier=entity_id)
    raw = queries.collection(db, kind, params, after)
    if not raw["entity_found"]:
        raise ApiError(404, "entity_not_found", "Entity not found in this activity scope")
    rows = raw["items"][: filters.limit]
    cursor = None
    if len(raw["items"]) > filters.limit:
        cursor = codec.next(anchor, views._timestamp(rows[-1]["moment"]), UUID(rows[-1]["id"]))
    return {
        "scope": views.scope(filters, params),
        "items": [item["data"] for item in rows],
        "total": raw["total"],
        "next_cursor": cursor,
        "index_status": views.status(raw["index_status"]),
    }


@router.get("/{entity_id}/events", response_model=EntityPage[EventActivity])
def events(
    entity_id: UUID,
    filters: Annotated[EntityFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> Any:
    return _collection("events", entity_id, filters, request, response, db, principal)


@router.get("/{entity_id}/alerts", response_model=EntityPage[EntityAlert])
def alerts(
    entity_id: UUID,
    filters: Annotated[EntityFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> Any:
    return _collection("alerts", entity_id, filters, request, response, db, principal)


@router.get("/{entity_id}/incidents", response_model=EntityPage[EntityIncident])
def incidents(
    entity_id: UUID,
    filters: Annotated[EntityFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> Any:
    return _collection("incidents", entity_id, filters, request, response, db, principal)
