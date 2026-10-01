"""Bounded operator status and audited, version-checked recovery."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Response
from sqlalchemy import func, select

from app.api.dependencies import DB, Principal, require
from app.api.sources import SourceAdmin
from app.api.users import lock_administration
from app.core.errors import ApiError
from app.core.permissions import Permission
from app.infrastructure.database import utcnow
from app.modules.audit.service import append_audit
from app.modules.detections.models import DetectionJob
from app.modules.normalization.models import PipelineJob

router = APIRouter(prefix="/api/v1", tags=["pipeline"])
Reader = Annotated[Principal, Depends(require(Permission.EVENTS_READ))]


def job_response(job: PipelineJob) -> dict[str, object]:
    return {
        "event_id": job.event_id,
        "state": job.state,
        "normalization_attempts": job.normalization_attempts,
        "projection_attempts": job.projection_attempts,
        "error_code": job.last_error_code,
        "version": job.version,
    }


@router.get("/events/{event_id}/pipeline")
def event_pipeline(
    event_id: UUID, response: Response, db: DB, principal: Reader
) -> dict[str, object]:
    job = db.get(PipelineJob, event_id)
    if job is None:
        raise ApiError(404, "not_found", "Event pipeline not found")
    response.headers.update({"Cache-Control": "no-store", "ETag": f'"{job.version}"'})
    return job_response(job)


@router.post("/events/{event_id}/pipeline/retry")
def retry_pipeline(
    event_id: UUID,
    request: Request,
    response: Response,
    db: DB,
    principal: SourceAdmin,
    if_match: Annotated[str | None, Header()] = None,
) -> dict[str, object]:
    if if_match is None:
        raise ApiError(428, "version_required", "If-Match is required")
    lock_administration(db, principal, request)
    job = db.scalar(select(PipelineJob).where(PipelineJob.event_id == event_id).with_for_update())
    if job is None:
        raise ApiError(404, "not_found", "Event pipeline not found")
    if if_match != f'"{job.version}"':
        raise ApiError(412, "version_conflict", "Refresh the resource before retrying")
    if job.state not in {"quarantined", "projection_failed"}:
        raise ApiError(409, "retry_not_allowed", "Only failed processing can be retried")
    previous = job.state
    if previous == "quarantined":
        job.state = "pending"
        job.normalization_attempts = 0
    else:
        job.state = "normalized"
        job.projection_attempts = 0
    job.available_at = utcnow()
    job.completed_at = None
    job.last_error_code = None
    job.lease_token = None
    job.lease_until = None
    append_audit(
        db,
        action="events.pipeline_retried",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=principal.user.id,
        object_type="event",
        object_id=str(event_id),
        details={"previous_state": previous},
    )
    db.commit()
    response.headers.update({"Cache-Control": "no-store", "ETag": f'"{job.version}"'})
    return job_response(job)


@router.get("/system/pipeline")
def pipeline_status(
    response: Response,
    db: DB,
    principal: Annotated[Principal, Depends(require(Permission.SYSTEM_READ))],
) -> dict[str, object]:
    states = {
        state: count
        for state, count in db.execute(
            select(PipelineJob.state, func.count()).group_by(PipelineJob.state)
        ).all()
    }
    oldest = db.scalar(
        select(func.min(PipelineJob.created_at)).where(
            PipelineJob.state.in_(["pending", "normalizing", "normalized", "projecting"])
        )
    )
    response.headers["Cache-Control"] = "no-store"
    return {
        "states": states,
        "oldest_pending_seconds": max(0, int((utcnow() - oldest).total_seconds())) if oldest else 0,
    }


@router.get("/system/detections")
def detection_status(
    response: Response,
    db: DB,
    principal: Annotated[Principal, Depends(require(Permission.SYSTEM_READ))],
) -> dict[str, object]:
    states = {
        state: count
        for state, count in db.execute(
            select(DetectionJob.state, func.count()).group_by(DetectionJob.state)
        ).all()
    }
    oldest = db.scalar(
        select(func.min(DetectionJob.created_at)).where(DetectionJob.state == "pending")
    )
    response.headers["Cache-Control"] = "no-store"
    return {
        "states": states,
        "oldest_pending_seconds": max(0, int((utcnow() - oldest).total_seconds())) if oldest else 0,
    }
