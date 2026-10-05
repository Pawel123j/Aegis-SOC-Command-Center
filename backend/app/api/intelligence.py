"""Read the local catalog; publish explicit, versioned manager changes atomically."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text

from app.api.dependencies import DB, Principal, lock_authority, require
from app.core.cursors import CursorCodec
from app.core.errors import ApiError
from app.core.permissions import Permission, has_permission
from app.core.rate_limit import rate_limit
from app.modules.intelligence import service
from app.modules.intelligence.models import IOCIdentity, IOCRevision
from app.modules.intelligence.normalization import NORMALIZATION_VERSION, normalize_indicator
from app.modules.intelligence.providers import providers_view
from app.modules.intelligence.schemas import (
    ImportResult,
    IOCFilters,
    IOCHistory,
    IOCImport,
    IOCInput,
    IOCPage,
    IOCPatch,
    IOCView,
    LookupInput,
    LookupResult,
    RevisionView,
)

router = APIRouter(prefix="/api/v1/intelligence", tags=["intelligence"])
Reader = Annotated[Principal, Depends(require(Permission.INTELLIGENCE_READ))]
Manager = Annotated[Principal, Depends(require(Permission.INTELLIGENCE_MANAGE))]
Administrator = Annotated[Principal, Depends(require(Permission.SYSTEM_MANAGE))]


def _headers(response: Response, version: int | None = None) -> None:
    response.headers["Cache-Control"] = "no-store"
    if version is not None:
        response.headers["ETag"] = f'"{version}"'


def _cursor(request: Request, principal: Principal, filters: dict[str, Any]) -> CursorCodec:
    scope = {**filters, "user_id": str(principal.user.id), "path": str(request.url.path)}
    return CursorCodec(
        request.app.state.settings.jwt_secret.get_secret_value(),
        "aegis-intelligence-cursor-v1",
        scope,
    )


@router.get("/providers")
def providers(response: Response, principal: Reader) -> dict[str, Any]:
    _headers(response)
    return providers_view()


@router.get("/iocs", response_model=IOCPage)
def catalog(
    filters: Annotated[IOCFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> IOCPage:
    rate_limit(request, "intelligence-read", str(principal.user.id), 120, window_seconds=60)
    codec = _cursor(request, principal, filters.model_dump(mode="json", exclude={"cursor"}))
    anchor, after = codec.read(filters.cursor)
    items, total = service.catalogue(db, filters, anchor, after)
    cursor = None
    if len(items) > filters.limit:
        last = items[filters.limit - 1]
        cursor = codec.next(anchor, last.created_at, last.id)
    _headers(response)
    return IOCPage(
        items=items[: filters.limit],
        total=total,
        next_cursor=cursor,
        normalization_version=NORMALIZATION_VERSION,
    )


@router.post("/iocs", response_model=IOCView, status_code=201)
def create(
    data: IOCInput, request: Request, response: Response, db: DB, principal: Manager
) -> IOCView:
    rate_limit(request, "intelligence-write", str(principal.user.id), 30, window_seconds=60)
    lock_authority(db, principal, Permission.INTELLIGENCE_MANAGE, request)
    result, created = service.create_ioc(
        db, data, actor=principal.user.id, request_id=request.state.request_id
    )
    db.commit()
    response.status_code = 201 if created else 200
    _headers(response, result.version)
    return result


@router.get("/iocs/{ioc_id}", response_model=IOCView)
def detail(ioc_id: UUID, response: Response, db: DB, principal: Reader) -> IOCView:
    identity = service.record(db, ioc_id)
    result = service.ioc_view(identity, service._current(db, identity))
    _headers(response, result.version)
    return result


@router.patch("/iocs/{ioc_id}", response_model=IOCView)
def patch(
    ioc_id: UUID,
    data: IOCPatch,
    request: Request,
    response: Response,
    db: DB,
    principal: Manager,
    if_match: Annotated[str | None, Header()] = None,
) -> IOCView:
    if if_match is None:
        raise ApiError(428, "version_required", "If-Match is required")
    rate_limit(request, "intelligence-write", str(principal.user.id), 30, window_seconds=60)
    lock_authority(db, principal, Permission.INTELLIGENCE_MANAGE, request)
    identity = service.record(db, ioc_id, locked=True)
    if if_match != f'"{identity.version}"':
        raise ApiError(412, "version_conflict", "Refresh the IOC before updating")
    result = service.patch_ioc(
        db, identity, data, actor=principal.user.id, request_id=request.state.request_id
    )
    db.commit()
    _headers(response, result.version)
    return result


@router.get("/iocs/{ioc_id}/history", response_model=IOCHistory)
def history(
    ioc_id: UUID,
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(max_length=4096)] = None,
) -> IOCHistory:
    service.record(db, ioc_id)
    codec = _cursor(request, principal, {"limit": limit})
    anchor, after = codec.read(cursor)
    db.execute(text("SET LOCAL statement_timeout='3000ms'"))
    statement = select(IOCRevision).where(
        IOCRevision.ioc_id == ioc_id, IOCRevision.created_at <= anchor
    )
    total = int(db.scalar(select(func.count()).select_from(statement.subquery())) or 0)
    if after is not None:
        from sqlalchemy import tuple_

        statement = statement.where(tuple_(IOCRevision.created_at, IOCRevision.id) < after)
    rows = list(
        db.scalars(
            statement.order_by(IOCRevision.created_at.desc(), IOCRevision.id.desc()).limit(
                limit + 1
            )
        )
    )
    items = []
    for row in rows[:limit]:
        try:
            service.revision_document(row)
        except ValueError:
            raise ApiError(
                409,
                "intelligence_revision_integrity_mismatch",
                "Stored IOC revision proof is invalid",
            ) from None
        items.append(RevisionView.model_validate(row))
    next_cursor = (
        codec.next(anchor, rows[limit - 1].created_at, rows[limit - 1].id)
        if len(rows) > limit
        else None
    )
    _headers(response)
    return IOCHistory(items=items, total=total, next_cursor=next_cursor)


@router.post("/import", response_model=ImportResult)
def import_iocs(
    data: IOCImport, request: Request, response: Response, db: DB, principal: Manager
) -> ImportResult:
    rate_limit(request, "intelligence-import", str(principal.user.id), 10, window_seconds=60)
    normalized = [service.normalized_input(item) for item in data.items]
    keys = {(item.type, item.value) for item in normalized}
    if len(keys) != len(normalized):
        raise ApiError(
            422, "ioc_import_duplicates", "Import contains duplicate canonical IOC identities"
        )
    lock_authority(db, principal, Permission.INTELLIGENCE_MANAGE, request)
    items, created = [], 0
    for item in normalized:
        result, new = service.create_ioc(
            db, item, actor=principal.user.id, request_id=request.state.request_id
        )
        items.append(result)
        created += int(new)
    db.commit()
    _headers(response)
    return ImportResult(items=items, created=created, unchanged=len(items) - created)


@router.post("/lookup", response_model=LookupResult)
def lookup(
    data: LookupInput, request: Request, response: Response, db: DB, principal: Reader
) -> LookupResult:
    rate_limit(request, "intelligence-lookup", str(principal.user.id), 60, window_seconds=60)
    try:
        value = normalize_indicator(data.type, data.value)
    except ValueError:
        raise ApiError(
            422, "indicator_invalid", "Indicator value is invalid for its type"
        ) from None
    identity = db.scalar(
        select(IOCIdentity).where(
            IOCIdentity.kind == data.type, IOCIdentity.canonical_value == value
        )
    )
    item = (
        service.ioc_view(identity, service._current(db, identity)) if identity is not None else None
    )
    _headers(response)
    return LookupResult(
        type=data.type,
        canonical_value=value,
        normalization_version=NORMALIZATION_VERSION,
        found=item is not None,
        item=item,
    )


@router.get("/events/{event_id}")
def event_matches(event_id: UUID, response: Response, db: DB, principal: Reader) -> dict[str, Any]:
    from app.modules.intelligence import matching

    if not has_permission(principal.user.role, Permission.EVENTS_READ):
        raise ApiError(403, "forbidden", "Permission denied")
    _headers(response)
    return matching.frozen_event(db, event_id)


class BackfillInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    limit: int = Field(default=25, strict=True, ge=1, le=100)


@router.post("/backfill")
def backfill(
    data: BackfillInput, request: Request, response: Response, db: DB, principal: Administrator
) -> dict[str, Any]:
    from app.modules.intelligence import matching

    rate_limit(request, "intelligence-backfill", str(principal.user.id), 30, window_seconds=60)
    lock_authority(db, principal, Permission.SYSTEM_MANAGE, request)
    result = matching.backfill(
        db, data.limit, actor_id=principal.user.id, request_id=request.state.request_id
    )
    db.commit()
    _headers(response)
    return result
