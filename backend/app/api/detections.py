"""Immutable initial rule catalog, versioned deployment toggles and pure rule testing."""

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.api.dependencies import DB, Principal, lock_authority, require
from app.core.errors import ApiError
from app.core.permissions import Permission
from app.core.rate_limit import rate_limit
from app.core.security import utcnow
from app.modules.audit.service import append_audit
from app.modules.detections.builtin import (
    BUILTIN_RULES,
    EVALUATOR_VERSION,
    BuiltinRule,
    evaluate_rule,
)
from app.modules.detections.models import RuleDeployment
from app.modules.mitre.mapping import rule_mapping
from app.modules.mitre.schemas import MappingView
from app.modules.normalization.schemas import NormalizedSecurityEvent

router = APIRouter(prefix="/api/v1/detections", tags=["detections"])
Reader = Annotated[Principal, Depends(require(Permission.DETECTIONS_READ))]
Publisher = Annotated[Principal, Depends(require(Permission.DETECTIONS_PUBLISH))]
Tester = Annotated[Principal, Depends(require(Permission.DETECTIONS_TEST))]


class RuleView(BaseModel):
    mitre_mapping: MappingView
    id: str
    rule_version: str
    title: str
    description: str
    severity: str
    mitre: list[str]
    false_positive_guidance: list[str]
    references: list[str]
    type: str
    evaluator_version: str
    enabled: bool
    version: int
    updated_at: datetime
    updated_by: UUID | None


class RulePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = Field(strict=True)


class RuleTest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=64)
    events: list[NormalizedSecurityEvent] = Field(min_length=1, max_length=100)


def rule_definition(rule_id: str) -> BuiltinRule:
    for rule in BUILTIN_RULES:
        if rule.id == rule_id:
            return rule
    raise ApiError(404, "rule_not_found", "Rule not found")


def view(rule: BuiltinRule, deployment: RuleDeployment) -> RuleView:
    if deployment.rule_version != rule.version:
        raise ApiError(503, "rules_unavailable", "Rule deployment version is unavailable")
    values = rule.snapshot()
    values["mitre_mapping"] = rule_mapping(rule.id)
    values.update(
        {
            "rule_version": rule.version,
            "version": deployment.version,
            "enabled": deployment.enabled,
            "updated_at": deployment.updated_at,
            "updated_by": deployment.updated_by,
        }
    )
    return RuleView.model_validate(values)


@router.get("")
def list_rules(response: Response, db: DB, principal: Reader) -> dict[str, list[RuleView]]:
    records = {row.id: row for row in db.scalars(select(RuleDeployment))}
    response.headers["Cache-Control"] = "no-store"
    try:
        return {"items": [view(rule, records[rule.id]) for rule in BUILTIN_RULES]}
    except KeyError:
        raise ApiError(503, "rules_unavailable", "Rule catalog temporarily unavailable") from None


@router.post("/test")
def test_rule(
    data: RuleTest, request: Request, response: Response, principal: Tester
) -> dict[str, Any]:
    rate_limit(request, "rule-test", str(principal.user.id), 30, window_seconds=60)
    rule = rule_definition(data.id)
    results = []
    for event in data.events:
        for match in evaluate_rule(rule.id, event.model_dump(mode="json")):
            results.append({"event_id": str(event.event_id), "reason": match.reason})
    response.headers["Cache-Control"] = "no-store"
    return {
        "rule_id": rule.id,
        "rule_version": rule.version,
        "evaluator_version": EVALUATOR_VERSION,
        "matches": results,
    }


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
    if deployment is None:
        raise ApiError(503, "rules_unavailable", "Rule catalog temporarily unavailable")
    if if_match != f'"{deployment.version}"':
        raise ApiError(412, "version_conflict", "Refresh the rule before updating")
    if deployment.rule_version != rule.version:
        raise ApiError(503, "rules_unavailable", "Rule deployment version is unavailable")
    if deployment.enabled == data.enabled:
        raise ApiError(409, "rule_unchanged", "Rule already has this deployment state")
    previous = deployment.enabled
    deployment.enabled = data.enabled
    deployment.updated_at = utcnow()
    deployment.updated_by = principal.user.id
    append_audit(
        db,
        action="detection.deployment_changed",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=principal.user.id,
        object_type="detection",
        object_id=rule.id,
        details={"rule_version": rule.version, "before": previous, "after": data.enabled},
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["ETag"] = f'"{deployment.version}"'
    return view(rule, deployment)
