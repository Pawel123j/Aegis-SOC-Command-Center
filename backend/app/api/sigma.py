"""Import disabled Sigma revisions and publish explicitly with optimistic authority."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Response
from sqlalchemy import func, select, text

from app.api.dependencies import DB, Principal, lock_authority, require
from app.core.errors import ApiError
from app.core.permissions import Permission
from app.core.rate_limit import rate_limit
from app.core.security import utcnow
from app.modules.audit.service import append_audit
from app.modules.detections.models import RuleDeployment
from app.modules.sigma.compiler import (
    EVALUATOR_VERSION,
    CompiledRule,
    SigmaValidationError,
    capabilities,
    compile_rule,
)
from app.modules.sigma.evaluator import evaluate
from app.modules.sigma.models import SigmaRule, SigmaRuleVersion
from app.modules.sigma.schemas import DeploymentPatch, RuleDetail, RuleView, TestInput, YamlInput
from app.modules.sigma.service import (
    MAX_REVISIONS,
    MAX_RULES,
    current_version,
    definition_view,
    rule_view,
    verified_version,
)

router = APIRouter(prefix="/api/v1/sigma", tags=["sigma"])
Reader = Annotated[Principal, Depends(require(Permission.DETECTIONS_READ))]
Importer = Annotated[Principal, Depends(require(Permission.DETECTIONS_IMPORT))]
Publisher = Annotated[Principal, Depends(require(Permission.DETECTIONS_PUBLISH))]
Tester = Annotated[Principal, Depends(require(Permission.DETECTIONS_TEST))]


def _compile(source: str) -> CompiledRule:
    try:
        return compile_rule(source)
    except SigmaValidationError as error:
        raise ApiError(422, f"sigma_{error.code}", error.message) from None


def _headers(response: Response, version: int | None = None) -> None:
    response.headers["Cache-Control"] = "no-store"
    if version is not None:
        response.headers["ETag"] = f'"{version}"'


def _record(db: DB, identity: UUID, *, locked: bool = False) -> tuple[SigmaRule, RuleDeployment]:
    statement = (
        select(SigmaRule, RuleDeployment)
        .join(RuleDeployment, RuleDeployment.id == SigmaRule.detection_id)
        .where(SigmaRule.id == identity)
    )
    if locked:
        statement = statement.with_for_update(of=RuleDeployment).execution_options(
            populate_existing=True
        )
    result = db.execute(statement).first()
    if result is None:
        raise ApiError(404, "sigma_rule_not_found", "Sigma rule not found")
    return result[0], result[1]


def _detail(db: DB, rule: SigmaRule, deployment: RuleDeployment) -> RuleDetail:
    result = rule_view(db, rule, deployment, detail=True)
    assert isinstance(result, RuleDetail)
    return result


def _current(db: DB, rule: SigmaRule, deployment: RuleDeployment) -> SigmaRuleVersion:
    try:
        row = current_version(db, rule, deployment)
        verified_version(row)
        return row
    except (ValueError, TypeError, KeyError):
        raise ApiError(503, "sigma_revision_unavailable", "Sigma revision is unavailable") from None


def _revision(
    db: DB, compiled: CompiledRule, source: str, revision: int, actor: UUID
) -> SigmaRuleVersion:
    row = SigmaRuleVersion(
        rule_id=compiled.sigma_id,
        revision=revision,
        definition_yaml=source,
        source_sha256=compiled.source_sha256,
        compiled_sha256=compiled.compiled_sha256,
        compiled=compiled.as_dict(),
        evaluator_version=EVALUATOR_VERSION,
        created_by=actor,
    )
    db.add(row)
    db.flush()
    db.execute(
        text("SELECT public.aegis_select_sigma_revision(:rule,:revision,:actor)"),
        {"rule": compiled.sigma_id, "revision": revision, "actor": actor},
    )
    return row


@router.get("/capabilities")
def get_capabilities(response: Response, principal: Reader) -> dict[str, Any]:
    _headers(response)
    return {
        **capabilities(),
        "max_rules": MAX_RULES,
        "max_revisions": MAX_REVISIONS,
        "max_test_events": 25,
        "max_test_body_bytes": 1048576,
        "max_import_body_bytes": 262144,
        "risk_policy": "risk-policy-v3",
        "risk_contribution": "declared-severity-only",
        "imported_rules_enabled_by_default": False,
    }


@router.post("/validate")
def validate_rule(
    data: YamlInput, request: Request, response: Response, principal: Reader
) -> dict[str, Any]:
    rate_limit(request, "sigma-validate", str(principal.user.id), 30, window_seconds=60)
    definition = _compile(data.yaml)
    _headers(response)
    return {
        "valid": True,
        "definition": definition_view(definition),
        "warnings": [
            "Supported subset only; validate locally, review source and enable explicitly.",
            "Declared severity is not attack confidence or confirmed behaviour.",
        ],
    }


@router.post("/test")
def test_rule(
    data: TestInput, request: Request, response: Response, principal: Tester
) -> dict[str, Any]:
    rate_limit(request, "sigma-test", str(principal.user.id), 30, window_seconds=60)
    definition = _compile(data.yaml)
    results = []
    for event in data.events:
        reason = evaluate(definition, event.model_dump(mode="json"))
        if reason is not None:
            results.append({"event_id": str(event.event_id), "reason": reason})
    _headers(response)
    return {
        "definition": definition_view(definition),
        "matches": results,
        "tested_events": len(data.events),
    }


@router.get("/rules")
def list_rules(response: Response, db: DB, principal: Reader) -> dict[str, list[RuleView]]:
    rows = db.execute(
        select(SigmaRule, RuleDeployment)
        .join(RuleDeployment, RuleDeployment.id == SigmaRule.detection_id)
        .order_by(SigmaRule.created_at.desc(), SigmaRule.id)
        .limit(MAX_RULES + 1)
    ).all()
    if len(rows) > MAX_RULES:
        raise ApiError(503, "sigma_rule_limit", "Sigma catalog exceeds supported bounds")
    _headers(response)
    return {"items": [rule_view(db, rule, deployment) for rule, deployment in rows]}


@router.get("/rules/{rule_id}", response_model=RuleDetail)
def rule_detail(rule_id: UUID, response: Response, db: DB, principal: Reader) -> RuleDetail:
    rule, deployment = _record(db, rule_id)
    result = _detail(db, rule, deployment)
    _headers(response, deployment.version)
    return result


@router.post("/rules", response_model=RuleDetail, status_code=201)
def import_rule(
    data: YamlInput, request: Request, response: Response, db: DB, principal: Importer
) -> RuleDetail:
    rate_limit(request, "sigma-import", str(principal.user.id), 20, window_seconds=60)
    lock_authority(db, principal, Permission.DETECTIONS_IMPORT, request)
    compiled = _compile(data.yaml)
    existing = db.get(SigmaRule, compiled.sigma_id)
    if existing is not None:
        rule, deployment = _record(db, compiled.sigma_id, locked=True)
        row = _current(db, rule, deployment)
        if row.source_sha256 != compiled.source_sha256:
            raise ApiError(
                409, "sigma_rule_exists", "Import a new revision explicitly for this Sigma ID"
            )
        response.status_code = 200
        _headers(response, deployment.version)
        return _detail(db, rule, deployment)
    count = db.scalar(select(func.count()).select_from(SigmaRule)) or 0
    if count >= MAX_RULES:
        raise ApiError(409, "sigma_rule_limit", "Sigma rule limit reached")
    rule = SigmaRule(
        id=compiled.sigma_id,
        detection_id=f"sigma:{compiled.sigma_id}",
        created_by=principal.user.id,
    )
    db.add(rule)
    db.flush()
    row = _revision(db, compiled, data.yaml, 1, principal.user.id)
    append_audit(
        db,
        action="sigma.imported",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=principal.user.id,
        object_type="sigma_rule",
        object_id=str(rule.id),
        details={
            "revision": 1,
            "revision_id": str(row.id),
            "source_sha256": row.source_sha256,
            "compiled_sha256": row.compiled_sha256,
            "enabled": False,
        },
    )
    db.commit()
    rule, deployment = _record(db, rule.id)
    _headers(response, deployment.version)
    return _detail(db, rule, deployment)


@router.post("/rules/{rule_id}/versions", response_model=RuleDetail, status_code=201)
def import_revision(
    rule_id: UUID,
    data: YamlInput,
    request: Request,
    response: Response,
    db: DB,
    principal: Importer,
    if_match: Annotated[str | None, Header()] = None,
) -> RuleDetail:
    if if_match is None:
        raise ApiError(428, "version_required", "If-Match is required")
    rate_limit(request, "sigma-import", str(principal.user.id), 20, window_seconds=60)
    lock_authority(db, principal, Permission.DETECTIONS_IMPORT, request)
    rule, deployment = _record(db, rule_id, locked=True)
    if if_match != f'"{deployment.version}"':
        raise ApiError(412, "version_conflict", "Refresh the Sigma rule before updating")
    compiled = _compile(data.yaml)
    if compiled.sigma_id != rule.id:
        raise ApiError(409, "sigma_id_mismatch", "Sigma revision must preserve its rule ID")
    prior = _current(db, rule, deployment)
    if prior.source_sha256 == compiled.source_sha256:
        raise ApiError(409, "sigma_definition_unchanged", "Sigma definition is unchanged")
    if prior.revision >= MAX_REVISIONS:
        raise ApiError(409, "sigma_revision_limit", "Sigma revision limit reached")
    row = _revision(db, compiled, data.yaml, prior.revision + 1, principal.user.id)
    append_audit(
        db,
        action="sigma.revision_imported",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=principal.user.id,
        object_type="sigma_rule",
        object_id=str(rule.id),
        details={
            "revision": row.revision,
            "revision_id": str(row.id),
            "source_sha256": row.source_sha256,
            "compiled_sha256": row.compiled_sha256,
            "previous_revision": prior.revision,
            "enabled": False,
        },
    )
    db.commit()
    db.refresh(deployment)
    _headers(response, deployment.version)
    return _detail(db, rule, deployment)


@router.patch("/rules/{rule_id}", response_model=RuleDetail)
def publish_rule(
    rule_id: UUID,
    data: DeploymentPatch,
    request: Request,
    response: Response,
    db: DB,
    principal: Publisher,
    if_match: Annotated[str | None, Header()] = None,
) -> RuleDetail:
    if if_match is None:
        raise ApiError(428, "version_required", "If-Match is required")
    lock_authority(db, principal, Permission.DETECTIONS_PUBLISH, request)
    rule, deployment = _record(db, rule_id, locked=True)
    if if_match != f'"{deployment.version}"':
        raise ApiError(412, "version_conflict", "Refresh the Sigma rule before updating")
    _current(db, rule, deployment)
    if deployment.enabled == data.enabled:
        raise ApiError(409, "rule_unchanged", "Sigma rule already has this deployment state")
    previous = deployment.enabled
    deployment.enabled = data.enabled
    deployment.updated_at = utcnow()
    deployment.updated_by = principal.user.id
    append_audit(
        db,
        action="sigma.deployment_changed",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=principal.user.id,
        object_type="sigma_rule",
        object_id=str(rule.id),
        details={
            "revision": int(deployment.rule_version),
            "before": previous,
            "after": data.enabled,
        },
    )
    db.commit()
    _headers(response, deployment.version)
    return _detail(db, rule, deployment)
