"""Authenticated exact operational aggregates; polling uses normal session checks."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response

from app.api.dependencies import DB, Principal, require
from app.core.errors import ApiError
from app.core.permissions import Permission, has_permission
from app.core.rate_limit import rate_limit
from app.infrastructure.database import utcnow
from app.modules.dashboard.queries import dashboard
from app.modules.dashboard.schemas import DashboardFilters, DashboardReport

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])
Reader = Annotated[Principal, Depends(require(Permission.EVENTS_READ))]


@router.get("", response_model=DashboardReport)
def overview(
    filters: Annotated[DashboardFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> DashboardReport:
    if any(
        not has_permission(principal.user.role, permission)
        for permission in (
            Permission.ALERTS_READ,
            Permission.INCIDENTS_READ,
            Permission.DETECTIONS_READ,
        )
    ):
        raise ApiError(403, "forbidden", "Permission denied")
    rate_limit(request, "dashboard-read", str(principal.user.id), 30, window_seconds=60)
    response.headers["Cache-Control"] = "no-store"
    return dashboard(db, filters, utcnow())
