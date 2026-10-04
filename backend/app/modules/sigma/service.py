"""Validate source revisions at every trusted boundary; no historical rewriting."""

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.modules.alerts.models import Alert
from app.modules.detections.models import RuleDeployment
from app.modules.ingestion.schemas import canonical_json
from app.modules.mitre.catalogue import CATALOGUE_SHA256, CATALOGUE_VERSION
from app.modules.mitre.mapping import MAPPING_VERSION, associate
from app.modules.mitre.schemas import MappingView
from app.modules.sigma.compiler import EVALUATOR_VERSION, CompiledRule, compile_rule
from app.modules.sigma.evaluator import evaluate
from app.modules.sigma.models import SigmaRule, SigmaRuleVersion
from app.modules.sigma.schemas import DefinitionView, RuleDetail, RuleView, VersionView

MAX_RULES = 100
MAX_REVISIONS = 20


@lru_cache(maxsize=128)
def _compile_frozen(source: str) -> CompiledRule:
    return compile_rule(source)


def verified_version(row: SigmaRuleVersion) -> CompiledRule:
    compiled = _compile_frozen(row.definition_yaml)
    if (
        compiled.sigma_id != row.rule_id
        or compiled.source_sha256 != row.source_sha256
        or compiled.compiled_sha256 != row.compiled_sha256
        or row.evaluator_version != EVALUATOR_VERSION
        or row.compiled != compiled.as_dict()
        or hashlib.sha256(canonical_json(row.compiled)).hexdigest() != row.compiled_sha256
    ):
        raise ValueError("sigma_revision_integrity_mismatch")
    return compiled


def mapping(compiled: CompiledRule) -> MappingView:
    techniques = associate(compiled.mitre)
    return MappingView(
        status="mapped" if techniques else "unmapped",
        catalogue_version=CATALOGUE_VERSION,
        catalogue_hash=CATALOGUE_SHA256,
        mapping_version=MAPPING_VERSION,
        mapping_hash=hashlib.sha256(
            canonical_json(
                {
                    "version": MAPPING_VERSION,
                    "catalogue_hash": CATALOGUE_SHA256,
                    "origin": "validated-sigma-technique-tags",
                    "source_sha256": compiled.source_sha256,
                    "compiled_sha256": compiled.compiled_sha256,
                    "techniques": list(compiled.mitre),
                }
            )
        ).hexdigest(),
        techniques=techniques,
        reason="Validated Sigma tags are candidate catalogue associations; they do not "
        "establish attack, success, attacker intent or risk context."
        if techniques
        else "No validated ATT&CK technique tag was supplied in this Sigma revision.",
    )


def definition_view(compiled: CompiledRule) -> DefinitionView:
    return DefinitionView(
        sigma_id=compiled.sigma_id,
        title=compiled.title,
        description=compiled.description,
        severity=compiled.severity,
        mitre=list(compiled.mitre),
        false_positive_guidance=list(compiled.false_positive_guidance),
        references=list(compiled.references),
        evaluator_version=EVALUATOR_VERSION,
        source_types=list(compiled.source_types),
        source_sha256=compiled.source_sha256,
        compiled_sha256=compiled.compiled_sha256,
        mitre_mapping=mapping(compiled),
    )


def current_version(db: Session, rule: SigmaRule, deployment: RuleDeployment) -> SigmaRuleVersion:
    if deployment.id != rule.detection_id:
        raise ValueError("sigma_deployment_integrity_mismatch")
    rows = list(
        db.scalars(
            select(SigmaRuleVersion)
            .where(
                SigmaRuleVersion.rule_id == rule.id,
                SigmaRuleVersion.revision == int(deployment.rule_version),
            )
            .limit(2)
        )
    )
    if len(rows) != 1 or str(rows[0].revision) != deployment.rule_version:
        raise ValueError("sigma_current_revision_unavailable")
    return rows[0]


def rule_view(
    db: Session, rule: SigmaRule, deployment: RuleDeployment, *, detail: bool = False
) -> RuleView | RuleDetail:
    try:
        row = current_version(db, rule, deployment)
        compiled = verified_version(row)
        values = definition_view(compiled).model_dump()
        values.update(
            id=rule.id,
            revision=row.revision,
            revision_id=row.id,
            enabled=deployment.enabled,
            version=deployment.version,
            updated_at=deployment.updated_at,
            updated_by=deployment.updated_by,
        )
        if detail:
            versions = list(
                db.scalars(
                    select(SigmaRuleVersion)
                    .where(SigmaRuleVersion.rule_id == rule.id)
                    .order_by(SigmaRuleVersion.revision.desc())
                    .limit(MAX_REVISIONS + 1)
                )
            )
            if len(versions) > MAX_REVISIONS:
                raise ValueError("sigma_revision_limit")
            return RuleDetail(
                **values,
                definition_yaml=row.definition_yaml,
                compiled=compiled.as_dict(),
                versions=[VersionView.model_validate(item) for item in versions],
            )
        return RuleView(**values)
    except (ValueError, TypeError, KeyError):
        raise ApiError(503, "sigma_revision_unavailable", "Sigma revision is unavailable") from None


@dataclass(frozen=True)
class RuntimeRule:
    revision: SigmaRuleVersion
    deployment: RuleDeployment
    compiled: CompiledRule

    @property
    def id(self) -> str:
        return self.deployment.id

    @property
    def version(self) -> str:
        return str(self.revision.revision)

    @property
    def title(self) -> str:
        return self.compiled.title

    @property
    def severity(self) -> str:
        return self.compiled.severity

    def snapshot(self) -> dict[str, Any]:
        values = self.compiled.snapshot()
        values.update(
            id=self.id,
            version=self.version,
            revision_id=str(self.revision.id),
            definition_yaml=self.revision.definition_yaml,
            compiled=self.compiled.as_dict(),
            deployment_version=self.deployment.version,
        )
        return values


@dataclass(frozen=True)
class SigmaMatch:
    rule: RuntimeRule
    reason: dict[str, Any]


def active_rules(db: Session) -> list[RuntimeRule]:
    records = db.execute(
        select(SigmaRule, RuleDeployment)
        .join(RuleDeployment, RuleDeployment.id == SigmaRule.detection_id)
        .where(RuleDeployment.enabled.is_(True))
        .order_by(SigmaRule.id)
        .limit(MAX_RULES + 1)
    ).all()
    if len(records) > MAX_RULES:
        raise ValueError("sigma_rule_limit")
    result = []
    for rule, deployment in records:
        row = current_version(db, rule, deployment)
        result.append(RuntimeRule(row, deployment, verified_version(row)))
    return result


def matches(rules: list[RuntimeRule], document: dict[str, Any]) -> list[SigmaMatch]:
    result = []
    for rule in rules:
        reason = evaluate(rule.compiled, document)
        if reason is not None:
            result.append(SigmaMatch(rule, reason))
    return result


def verified_alert(db: Session, alert: Alert) -> CompiledRule:
    """Read immutable original revision, never the latest deployment as historical proof."""
    try:
        row = db.get(SigmaRuleVersion, UUID(alert.rule_snapshot["revision_id"]))
        if row is None:
            raise ValueError("sigma_revision_missing")
        compiled = verified_version(row)
        frozen = compiled.snapshot()
        frozen.update(
            id=f"sigma:{row.rule_id}",
            version=str(row.revision),
            revision_id=str(row.id),
            definition_yaml=row.definition_yaml,
            compiled=compiled.as_dict(),
            deployment_version=alert.rule_snapshot["deployment_version"],
        )
        if (
            alert.rule_snapshot != frozen
            or alert.rule_id != frozen["id"]
            or alert.rule_version != str(row.revision)
            or alert.severity != compiled.severity
            or alert.evaluator_version != EVALUATOR_VERSION
            or alert.title != compiled.title
            or not isinstance(frozen["deployment_version"], int)
            or isinstance(frozen["deployment_version"], bool)
            or frozen["deployment_version"] < 1
            or evaluate(compiled, alert.event_snapshot) != alert.reason
        ):
            raise ValueError("sigma_alert_integrity_mismatch")
        return compiled
    except (ValueError, TypeError, KeyError):
        raise ValueError("sigma_alert_integrity_mismatch") from None
