"""Human-authorized normalized Event Explorer, isolated from ingestion credentials."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response

from app.api.dependencies import Principal, require
from app.core.errors import ApiError
from app.core.permissions import Permission
from app.core.rate_limit import rate_limit
from app.modules.events.clickhouse import ClickHouseEvents, ClickHouseUnavailable
from app.modules.events.schemas import SearchParams, SearchRequest, SearchResult
from app.modules.events.service import CursorError, search
from app.modules.normalization.schemas import NormalizedSecurityEvent

router = APIRouter(prefix="/api/v1/events", tags=["events"])
Reader = Annotated[Principal, Depends(require(Permission.EVENTS_READ))]


def run_search(
    data: SearchRequest, request: Request, response: Response, principal: Principal
) -> SearchResult:
    rate_limit(request, "event-search", str(principal.user.id), 60, window_seconds=60)
    response.headers["Cache-Control"] = "no-store"
    try:
        return search(request.app.state.settings, data, principal.user.id)
    except (CursorError, ValueError):
        raise ApiError(422, "invalid_search", "Search window or cursor is invalid") from None
    except ClickHouseUnavailable:
        raise ApiError(503, "archive_unavailable", "Event search temporarily unavailable") from None


@router.post("/search", response_model=SearchResult)
def search_events(
    data: SearchRequest, request: Request, response: Response, principal: Reader
) -> SearchResult:
    return run_search(data, request, response, principal)


@router.get("", response_model=SearchResult)
def list_events(
    data: Annotated[SearchParams, Query()], request: Request, response: Response, principal: Reader
) -> SearchResult:
    return run_search(data, request, response, principal)


@router.get("/{event_id}", response_model=NormalizedSecurityEvent)
def event_detail(
    event_id: UUID, request: Request, response: Response, principal: Reader
) -> NormalizedSecurityEvent:
    rate_limit(request, "event-detail", str(principal.user.id), 60, window_seconds=60)
    response.headers["Cache-Control"] = "no-store"
    try:
        document = ClickHouseEvents(request.app.state.settings).get_event(event_id)
    except ClickHouseUnavailable:
        raise ApiError(503, "archive_unavailable", "Event search temporarily unavailable") from None
    if document is None:
        raise ApiError(404, "event_not_found", "Event not found")
    return NormalizedSecurityEvent.model_validate(document)
