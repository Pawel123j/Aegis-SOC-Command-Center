"""Authenticated offline catalogue and scope-explicit candidate association counts."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response

from app.api.dependencies import DB, Principal, require
from app.core.errors import ApiError
from app.core.permissions import Permission, has_permission
from app.core.rate_limit import rate_limit
from app.infrastructure.database import utcnow
from app.modules.mitre.catalogue import catalogue_view
from app.modules.mitre.coverage import coverage
from app.modules.mitre.schemas import CatalogueView, CoverageFilters, CoverageView

router = APIRouter(prefix="/api/v1/mitre", tags=["mitre"])
Reader = Annotated[Principal, Depends(require(Permission.DETECTIONS_READ))]


@router.get("/catalog", response_model=CatalogueView)
def catalog(response: Response, principal: Reader) -> CatalogueView:
    response.headers["Cache-Control"] = "no-store"
    return catalogue_view()


@router.get("/coverage", response_model=CoverageView)
def coverage_view(
    filters: Annotated[CoverageFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> CoverageView:
    if not all(
        has_permission(principal.user.role, permission)
        for permission in (Permission.ALERTS_READ, Permission.INCIDENTS_READ)
    ):
        raise ApiError(403, "forbidden", "Permission denied")
    rate_limit(request, "mitre-coverage", str(principal.user.id), 60, window_seconds=60)
    response.headers["Cache-Control"] = "no-store"
    return coverage(db, filters, utcnow())
