"""Authenticated read-only assessments and explicit bounded recalculation."""

from typing import Annotated, Any, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from sqlalchemy import select

from app.api.dependencies import DB, Principal, lock_authority, require
from app.core.errors import ApiError
from app.core.permissions import Permission
from app.core.rate_limit import rate_limit
from app.modules.alerts.models import Alert
from app.modules.incidents.models import Incident
from app.modules.risk import service
from app.modules.risk.engine import POLICY_HASH, POLICY_VERSION, calculate, policy_view
from app.modules.risk.schemas import BackfillInput, RiskHistory, RiskInput

router = APIRouter(prefix="/api/v1", tags=["risk"])
Reader = Annotated[Principal, Depends(require(Permission.DETECTIONS_READ))]
AlertReader = Annotated[Principal, Depends(require(Permission.ALERTS_READ))]
IncidentReader = Annotated[Principal, Depends(require(Permission.INCIDENTS_READ))]
AlertEditor = Annotated[Principal, Depends(require(Permission.ALERTS_MANAGE))]
IncidentEditor = Annotated[Principal, Depends(require(Permission.INCIDENTS_EDIT))]
Administrator = Annotated[Principal, Depends(require(Permission.SYSTEM_MANAGE))]
Tester = Annotated[Principal, Depends(require(Permission.DETECTIONS_TEST))]


def _read(db: DB, identifier: UUID, kind: Literal["alert", "incident"]) -> Alert | Incident:
    row = db.get(Alert if kind == "alert" else Incident, identifier)
    if row is None:
        raise ApiError(404, f"{kind}_not_found", f"{kind.title()} not found")
    return cast(Alert | Incident, row)


@router.get("/risk/policy")
def policy(response: Response, principal: Reader) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    return policy_view()


@router.post("/risk/test")
def test_risk(
    data: RiskInput, request: Request, response: Response, principal: Tester
) -> dict[str, Any]:
    rate_limit(request, "risk-test", str(principal.user.id), 30, window_seconds=60)
    response.headers["Cache-Control"] = "no-store"
    try:
        result = calculate(data)
    except ValueError:
        raise ApiError(422, "invalid_risk_input", "Risk inputs conflict") from None
    return {
        "simulation": True,
        "policy_version": POLICY_VERSION,
        "policy_hash": POLICY_HASH,
        **result.model_dump(mode="json"),
    }


@router.post("/risk/backfill")
def backfill(
    data: BackfillInput, request: Request, response: Response, db: DB, principal: Administrator
) -> dict[str, Any]:
    rate_limit(request, "risk-backfill", str(principal.user.id), 30, window_seconds=60)
    lock_authority(db, principal, Permission.SYSTEM_MANAGE, request)
    result = service.backfill(
        db, data.limit, request_id=request.state.request_id, actor_id=principal.user.id
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return result


@router.get("/alerts/{alert_id}/risk", response_model=RiskHistory)
def alert_risk(
    alert_id: UUID,
    response: Response,
    db: DB,
    principal: AlertReader,
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> RiskHistory:
    response.headers["Cache-Control"] = "no-store"
    return service.history(db, _read(db, alert_id, "alert"), limit)


@router.get("/incidents/{incident_id}/risk", response_model=RiskHistory)
def incident_risk(
    incident_id: UUID,
    response: Response,
    db: DB,
    principal: IncidentReader,
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> RiskHistory:
    response.headers["Cache-Control"] = "no-store"
    return service.history(db, _read(db, incident_id, "incident"), limit)


def _recalculate(
    db: DB,
    identifier: UUID,
    kind: Literal["alert", "incident"],
    principal: Principal,
    request: Request,
    response: Response,
    if_match: str | None,
) -> RiskHistory:
    if if_match is None:
        raise ApiError(428, "version_required", "If-Match is required")
    permission = Permission.ALERTS_MANAGE if kind == "alert" else Permission.INCIDENTS_EDIT
    rate_limit(request, f"risk-recalculate-{kind}", str(principal.user.id), 30, window_seconds=60)
    lock_authority(db, principal, permission, request)
    model = Alert if kind == "alert" else Incident
    row = cast(
        Alert | Incident | None,
        db.scalar(
            select(model)
            .where(model.id == identifier)
            .with_for_update()
            .execution_options(populate_existing=True)
        ),
    )
    if row is None:
        raise ApiError(404, f"{kind}_not_found", f"{kind.title()} not found")
    if if_match != f'"{row.version}"':
        raise ApiError(412, "version_conflict", "Refresh the subject before recalculating")
    service.score_subject(
        db,
        row,
        request_id=request.state.request_id,
        actor_id=principal.user.id,
        trigger="analyst_recalculation",
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["ETag"] = f'"{row.version}"'
    return service.history(db, row, 10)


@router.post("/alerts/{alert_id}/risk/recalculate", response_model=RiskHistory)
def recalculate_alert(
    alert_id: UUID,
    request: Request,
    response: Response,
    db: DB,
    principal: AlertEditor,
    if_match: Annotated[str | None, Header()] = None,
) -> RiskHistory:
    return _recalculate(db, alert_id, "alert", principal, request, response, if_match)


@router.post("/incidents/{incident_id}/risk/recalculate", response_model=RiskHistory)
def recalculate_incident(
    incident_id: UUID,
    request: Request,
    response: Response,
    db: DB,
    principal: IncidentEditor,
    if_match: Annotated[str | None, Header()] = None,
) -> RiskHistory:
    return _recalculate(db, incident_id, "incident", principal, request, response, if_match)
