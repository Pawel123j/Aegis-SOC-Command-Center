"""Native temporal catalog, current-authority deployments, pure tests and coverage."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Request, Response
from sqlalchemy import func, select

from app.api.dependencies import DB, Principal, lock_authority, require
from app.api.detections import RulePatch
from app.core.errors import ApiError
from app.core.permissions import Permission
from app.core.rate_limit import rate_limit
from app.infrastructure.database import utcnow
from app.modules.audit.service import append_audit
from app.modules.correlation.builtin import BUILTIN_RULES, rule_definition
from app.modules.correlation.contracts import (
    EVALUATOR_VERSION,
    CorrelationRule,
    ReplayFinalize,
    RuleTest,
    RuleView,
)
from app.modules.correlation.engine import evaluate_anchor
from app.modules.correlation.models import CorrelationJob, CorrelationScope
from app.modules.correlation.replay import finalize_replay, seal_view
from app.modules.detections.models import RuleDeployment

router = APIRouter(prefix="/api/v1/correlations", tags=["correlations"])
Reader = Annotated[Principal, Depends(require(Permission.DETECTIONS_READ))]
Publisher = Annotated[Principal, Depends(require(Permission.DETECTIONS_PUBLISH))]
Tester = Annotated[Principal, Depends(require(Permission.DETECTIONS_TEST))]


def view(rule: CorrelationRule, deployment: RuleDeployment) -> RuleView:
    if deployment.rule_version != rule.version:
        raise ApiError(503, "rules_unavailable", "Rule deployment version is unavailable")
    return RuleView.model_validate(
        {
            **rule.snapshot(),
            "rule_version": rule.version,
            "version": deployment.version,
            "enabled": deployment.enabled,
            "updated_at": deployment.updated_at,
            "updated_by": deployment.updated_by,
        }
    )


@router.get("")
def list_rules(response: Response, db: DB, principal: Reader) -> dict[str, list[RuleView]]:
    records = {row.id: row for row in db.scalars(select(RuleDeployment))}
    response.headers["Cache-Control"] = "no-store"
    try:
        return {"items": [view(rule, records[rule.id]) for rule in BUILTIN_RULES]}
    except KeyError:
        raise ApiError(503, "rules_unavailable", "Rule catalog temporarily unavailable") from None


@router.get("/status")
def correlation_status(response: Response, db: DB, principal: Reader) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    counts = {
        state: int(count)
        for state, count in db.execute(
            select(CorrelationJob.state, func.count()).group_by(CorrelationJob.state)
        )
    }
    scopes = (
        db.execute(
            select(
                CorrelationScope.namespace,
                CorrelationScope.watermark,
                CorrelationScope.sealed_at,
                CorrelationScope.manifest_sha256,
                func.jsonb_array_length(CorrelationScope.manifest).label("event_count"),
            )
            .order_by(CorrelationScope.namespace)
            .limit(101)
        )
        .mappings()
        .all()
    )
    return {
        "counts": counts,
        "scopes": [dict(scope) for scope in scopes[:100]],
        "scopes_truncated": len(scopes) > 100,
    }


@router.post("/test")
def test_rule(
    data: RuleTest, request: Request, response: Response, principal: Tester
) -> dict[str, Any]:
    rate_limit(request, "correlation-test", str(principal.user.id), 30, window_seconds=60)
    rule = rule_definition(data.id)
    if len({event.event_id for event in data.events}) != len(data.events):
        raise ApiError(422, "duplicate_event_id", "Correlation test events must have unique IDs")
    matches = [
        match
        for event in sorted(data.events, key=lambda row: (row.timestamp, row.event_id))
        if (match := evaluate_anchor(rule, event, data.events)) is not None
    ]
    response.headers["Cache-Control"] = "no-store"
    return {
        "rule_id": rule.id,
        "rule_version": rule.version,
        "evaluator_version": EVALUATOR_VERSION,
        "matches": matches,
        "complete": True,
    }


@router.post("/replay/finalize")
def finalize(
    data: ReplayFinalize, request: Request, response: Response, db: DB, principal: Publisher
) -> dict[str, Any]:
    lock_authority(db, principal, Permission.DETECTIONS_PUBLISH, request)
    scope = finalize_replay(
        db, data, actor_id=principal.user.id, request_id=request.state.request_id
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return seal_view(scope)


@router.get("/{rule_id}", response_model=RuleView)
def rule_detail(rule_id: str, response: Response, db: DB, principal: Reader) -> RuleView:
    rule = rule_definition(rule_id)
    deployment = db.get(RuleDeployment, rule_id)
    if deployment is None:
        raise ApiError(503, "rules_unavailable", "Rule catalog temporarily unavailable")
    response.headers["Cache-Control"] = "no-store"
    response.headers["ETag"] = f'"{deployment.version}"'
    return view(rule, deployment)


@router.patch("/{rule_id}", response_model=RuleView)
def update_rule(
    rule_id: str,
    data: RulePatch,
    request: Request,
    response: Response,
    db: DB,
    principal: Publisher,
    if_match: Annotated[str | None, Header()] = None,
) -> RuleView:
    if if_match is None:
        raise ApiError(428, "version_required", "If-Match is required")
    lock_authority(db, principal, Permission.DETECTIONS_PUBLISH, request)
    rule = rule_definition(rule_id)
    deployment = db.scalar(
        select(RuleDeployment)
        .where(RuleDeployment.id == rule_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if deployment is None or deployment.rule_version != rule.version:
        raise ApiError(503, "rules_unavailable", "Rule deployment version is unavailable")
    if if_match != f'"{deployment.version}"':
        raise ApiError(412, "version_conflict", "Refresh the rule before updating")
    if deployment.enabled == data.enabled:
        raise ApiError(409, "rule_unchanged", "Rule already has this deployment state")
    previous = deployment.enabled
    deployment.enabled, deployment.updated_at, deployment.updated_by = (
        data.enabled,
        utcnow(),
        principal.user.id,
    )
    append_audit(
        db,
        action="correlation.deployment_changed",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=principal.user.id,
        object_type="correlation",
        object_id=rule.id,
        details={"rule_version": rule.version, "before": previous, "after": data.enabled},
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["ETag"] = f'"{deployment.version}"'
    return view(rule, deployment)
