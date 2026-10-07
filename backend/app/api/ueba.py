"""Read-only entity behaviour reports with existing evidence-reader permissions."""

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response

from app.api.dependencies import DB, Principal, require
from app.core.errors import ApiError
from app.core.permissions import Permission, has_permission
from app.core.rate_limit import rate_limit
from app.modules.normalization.schemas import NormalizedSecurityEvent
from app.modules.ueba import queries, views
from app.modules.ueba.schemas import UebaEvidenceFilters, UebaFilters, UebaReport

router = APIRouter(prefix="/api/v1/entities", tags=["ueba"])
Reader = Annotated[Principal, Depends(require(Permission.EVENTS_READ))]


def _read_report(
    entity_id: UUID,
    filters: UebaFilters,
    request: Request,
    response: Response,
    db: DB,
    principal: Principal,
) -> tuple[dict[str, Any], UebaReport]:
    if not all(
        has_permission(principal.user.role, permission)
        for permission in (
            Permission.EVENTS_READ,
            Permission.ALERTS_READ,
            Permission.INCIDENTS_READ,
        )
    ):
        raise ApiError(403, "forbidden", "Permission denied")
    rate_limit(request, "ueba-reads", str(principal.user.id), 30, window_seconds=60)
    response.headers["Cache-Control"] = "no-store"
    try:
        start, observed_start, end = filters.window(datetime.now(UTC))
    except ValueError:
        raise ApiError(422, "invalid_ueba_day", "Select a complete past UTC day") from None
    data = queries.snapshot(db, entity_id, filters, start, end)
    return data, views.project(data, filters, start, observed_start, end)


@router.get("/{entity_id}/ueba", response_model=UebaReport)
def report(
    entity_id: UUID,
    filters: Annotated[UebaFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> UebaReport:
    return _read_report(entity_id, filters, request, response, db, principal)[1]


@router.get("/{entity_id}/ueba/events/{event_id}", response_model=NormalizedSecurityEvent)
def evidence(
    entity_id: UUID,
    event_id: UUID,
    filters: Annotated[UebaEvidenceFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> NormalizedSecurityEvent:
    data, current = _read_report(entity_id, filters, request, response, db, principal)
    # The report and the opened original share one verified PostgreSQL snapshot.
    # A late event can change the comparison; stale proof then requires refresh.
    if not any(
        proof.event_id == event_id and proof.document_sha256 == filters.document_sha256
        for indicator in current.indicators
        for proof in indicator.evidence
    ):
        raise ApiError(409, "ueba_changed", "Refresh the analysis before opening this evidence")
    row = next(item for item in data["items"] if item["normalized"]["event_id"] == str(event_id))
    return NormalizedSecurityEvent.model_validate(row["normalized"]["document"])
