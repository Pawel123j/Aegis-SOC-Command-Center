"""Observed chronology of source-verified active incident evidence."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response

from app.api.dependencies import DB, Principal, require
from app.core.errors import ApiError
from app.core.permissions import Permission, has_permission
from app.core.rate_limit import rate_limit
from app.modules.attack_timeline import queries, views
from app.modules.attack_timeline.cursors import TimelineCursor
from app.modules.attack_timeline.schemas import AttackTimeline, TimelineQuery

router = APIRouter(prefix="/api/v1/incidents", tags=["attack-timeline"])
Reader = Annotated[Principal, Depends(require(Permission.INCIDENTS_READ))]


@router.get("/{incident_id}/attack-timeline", response_model=AttackTimeline)
def timeline(
    incident_id: UUID,
    filters: Annotated[TimelineQuery, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> AttackTimeline:
    if not all(
        has_permission(principal.user.role, permission)
        for permission in (
            Permission.INCIDENTS_READ,
            Permission.ALERTS_READ,
            Permission.EVENTS_READ,
        )
    ):
        raise ApiError(403, "forbidden", "Permission denied")
    rate_limit(request, "attack-timeline-reads", str(principal.user.id), 60, window_seconds=60)
    response.headers["Cache-Control"] = "no-store"
    codec = TimelineCursor(
        request.app.state.settings.jwt_secret.get_secret_value(),
        {"user_id": str(principal.user.id), "path": str(request.url.path), "limit": filters.limit},
    )
    position = codec.read(filters.cursor)
    return views.project(
        queries.timeline(db, incident_id, filters.limit, position), codec, position
    )
