"""Persisted source/AST proof and severity-only priority are independently checked."""

import json
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.modules.alerts.models import Alert
from app.modules.detections.models import RuleDeployment
from app.modules.risk.engine import POLICY_VERSION, calculate
from app.modules.risk.schemas import EvidenceReference, RiskInput, SeverityBaseline, Signal
from app.modules.sigma.compiler import EVALUATOR_VERSION, compile_rule
from app.modules.sigma.evaluator import evaluate
from app.modules.sigma.models import SigmaRuleVersion
from app.modules.sigma.service import (
    RuntimeRule,
    definition_view,
    mapping,
    verified_alert,
    verified_version,
)


def source(**changes: Any) -> str:
    return json.dumps(
        {
            "title": "Own Sigma fixture",
            "id": "5946167f-0d59-4c36-9f9b-556ed30a01c7",
            "level": "high",
            "logsource": {"product": "aegis", "service": "generic_json"},
            "detection": {"selection": {"event.action": "review"}, "condition": "selection"},
            **changes,
        }
    )


def revision() -> SigmaRuleVersion:
    yaml = source()
    compiled = compile_rule(yaml)
    return SigmaRuleVersion(
        id=uuid4(),
        rule_id=compiled.sigma_id,
        revision=1,
        definition_yaml=yaml,
        source_sha256=compiled.source_sha256,
        compiled_sha256=compiled.compiled_sha256,
        compiled=compiled.as_dict(),
        evaluator_version=EVALUATOR_VERSION,
        created_by=uuid4(),
    )


def proof() -> tuple[Mock, Alert]:
    row = revision()
    compiled = verified_version(row)
    deployment = RuleDeployment(
        id=f"sigma:{row.rule_id}", rule_version="1", enabled=True, version=2
    )
    runtime = RuntimeRule(row, deployment, compiled)
    event = {"source": {"type": "generic_json"}, "event": {"action": "review"}}
    alert = Alert(
        id=uuid4(),
        rule_id=runtime.id,
        rule_version="1",
        severity="high",
        title=runtime.title,
        evaluator_version=EVALUATOR_VERSION,
        rule_snapshot=runtime.snapshot(),
        event_snapshot=event,
        reason=evaluate(compiled, event),
    )
    db = Mock(spec=Session)
    db.get.return_value = row
    return db, alert


@pytest.mark.parametrize(
    "field",
    [
        "definition_yaml",
        "source_sha256",
        "compiled_sha256",
        "compiled",
        "rule_id",
        "evaluator_version",
    ],
)
def test_revision_requires_recompile_source_and_both_hashes(field: str) -> None:
    row = revision()
    assert verified_version(row).sigma_id == row.rule_id
    replacements = {
        "definition_yaml": source(title="other"),
        "source_sha256": "a" * 64,
        "compiled_sha256": "b" * 64,
        "compiled": {},
        "rule_id": uuid4(),
        "evaluator_version": "other-v1",
    }
    setattr(row, field, replacements[field])
    with pytest.raises(ValueError, match="sigma_revision_integrity_mismatch"):
        verified_version(row)


@pytest.mark.parametrize(
    "field",
    [
        "rule_id",
        "rule_version",
        "severity",
        "title",
        "evaluator_version",
        "reason",
        "event_snapshot",
    ],
)
def test_historical_alert_requires_persisted_revision_and_matching_predicate(field: str) -> None:
    db, alert = proof()
    assert verified_alert(db, alert).title == alert.title
    changes = {
        "rule_id": "powershell-suspicious-command",
        "rule_version": "2",
        "severity": "critical",
        "title": "other",
        "evaluator_version": "single-event-v1",
        "reason": {},
        "event_snapshot": {"source": {"type": "generic_json"}, "event": {"action": "other"}},
    }
    setattr(alert, field, changes[field])
    with pytest.raises(ValueError, match="sigma_alert_integrity_mismatch"):
        verified_alert(db, alert)


@pytest.mark.parametrize("version", [0, True, "2", None])
def test_snapshot_requires_positive_integer_original_deployment_version(version: Any) -> None:
    db, alert = proof()
    alert.rule_snapshot = {**alert.rule_snapshot, "deployment_version": version}
    with pytest.raises(ValueError, match="sigma_alert_integrity_mismatch"):
        verified_alert(db, alert)


def test_missing_persisted_revision_is_not_replaced_by_self_reported_source() -> None:
    db, alert = proof()
    db.get.return_value = None
    with pytest.raises(ValueError, match="sigma_alert_integrity_mismatch"):
        verified_alert(db, alert)


def test_mapping_is_candidate_only_and_revision_hash_bound() -> None:
    first = compile_rule(source(tags=["attack.t1059.001"]))
    second = compile_rule(source(tags=["attack.t1059.001"], description="Changed source"))
    one, two = mapping(first), mapping(second)
    assert one.mapping_hash != two.mapping_hash
    assert one.techniques == two.techniques and one.confirmed_attack is False
    assert one.claim == "candidate_association"
    assert definition_view(first).source_sha256 == first.source_sha256
    assert mapping(compile_rule(source())).status == "unmapped"


def refs(count: int) -> list[EvidenceReference]:
    return [
        EvidenceReference(
            id=UUID(int=n + 1), timestamp=datetime(2026, 10, 1, tzinfo=UTC), sha256="a" * 64
        )
        for n in range(count)
    ]


@pytest.mark.parametrize(
    "severity,expected",
    [("informational", 5), ("low", 15), ("medium", 30), ("high", 45), ("critical", 55)],
)
def test_sigma_severity_changes_d_only_without_behavior_or_confidence(
    severity: str, expected: int
) -> None:
    evidence = refs(3)
    baseline = SeverityBaseline.model_validate(
        {"id": "sigma", "severity": severity, "evidence_ids": [item.id for item in evidence]}
    )
    result = calculate(RiskInput(evidence=evidence, severity_baselines=[baseline]))
    assert POLICY_VERSION == "risk-policy-v3" and result.score == expected
    components = {item.code: item for item in result.components}
    assert components["D"].points == expected and components["D"].status == "known"
    assert components["C"].points == components["E"].points == 0
    assert components["C"].status == components["E"].status == "unknown"
    assert result.signal_units == [] and result.confidence_status == "unknown"
    assert all(components[code].status == "unknown" for code in "A U I T H P".split())


def test_sigma_distinct_event_matches_cannot_claim_independent_units_or_qualified_event_bonus() -> (
    None
):
    evidence = refs(3)
    baselines = [
        SeverityBaseline(id=str(item.id), severity="high", evidence_ids=[item.id])
        for item in evidence
    ]
    result = calculate(RiskInput(evidence=evidence, severity_baselines=baselines))
    assert result.score == 45 and result.signal_units == []
    parts = {item.code: item for item in result.components}
    assert parts["E"].details["unique_events"] == 0 and parts["C"].details["independent_units"] == 0


def test_sigma_mixed_same_event_changes_max_d_but_keeps_builtin_ce_arithmetic() -> None:
    evidence = refs(2)
    signal = Signal(
        id="builtin",
        family="suspicious_execution",
        severity="high",
        evidence_ids=[item.id for item in evidence],
    )
    baseline = SeverityBaseline(id="sigma", severity="critical", evidence_ids=[evidence[0].id])
    original = calculate(RiskInput(evidence=evidence, signals=[signal]))
    result = calculate(
        RiskInput(evidence=evidence, signals=[signal], severity_baselines=[baseline])
    )
    assert result.score == 57 and original.score == 47
    assert result.signal_units == original.signal_units
    for code in ("C", "E"):
        assert next(item for item in result.components if item.code == code) == next(
            item for item in original.components if item.code == code
        )


def test_severity_baseline_cannot_supply_confidence_or_behavior_family() -> None:
    for extra in ({"confidence": 100}, {"family": "suspicious_execution"}):
        with pytest.raises(ValidationError):
            SeverityBaseline.model_validate(
                {"id": "a", "severity": "high", "evidence_ids": [UUID(int=1)], **extra}
            )


def test_baseline_refs_and_identity_are_bounded_and_unique() -> None:
    baseline = SeverityBaseline(id="a", severity="high", evidence_ids=[UUID(int=1)])
    with pytest.raises(ValidationError):
        RiskInput(severity_baselines=[baseline])
    with pytest.raises(ValueError, match="baseline identities"):
        calculate(RiskInput(evidence=refs(1), severity_baselines=[baseline, deepcopy(baseline)]))
