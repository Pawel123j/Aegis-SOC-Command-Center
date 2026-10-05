"""Golden IOC priority vectors around the unchanged behavioural policy and history."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from itertools import permutations
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.modules.ingestion.schemas import canonical_json
from app.modules.risk import engine as v3
from app.modules.risk import engine_v4 as v4
from app.modules.risk.schemas import ContextFact, EvidenceReference, Provenance, RiskInput, Signal

START = datetime(2026, 10, 5, 12, tzinfo=UTC)
PROVENANCE = Provenance(
    source="local-ioc-revision",
    version="1",
    snapshot_sha256="a" * 64,
    as_of=START - timedelta(days=1),
)


def evidence(count: int) -> list[EvidenceReference]:
    return [
        EvidenceReference(
            id=UUID(int=index + 1), timestamp=START + timedelta(seconds=index), sha256="b" * 64
        )
        for index in range(count)
    ]


def fact(value: str = "malicious", confidence: int | None = None, **extra: Any) -> ContextFact:
    return ContextFact.model_validate(
        {
            "kind": "ioc_reputation",
            "value": value,
            "confidence": confidence,
            "evidence_ids": [UUID(int=1)],
            "provenance": PROVENANCE,
            **extra,
        }
    )


def input_data(*, count: int = 1, ti: bool = False, **extra: Any) -> RiskInput:
    events = evidence(count)
    base: dict[str, Any] = {"evidence": events}
    if ti:
        base["severity_baselines"] = [
            {
                "id": f"{UUID(int=99)}:intelligence-severity",
                "severity": "medium",
                "evidence_ids": [events[0].id],
                "alert_ids": [UUID(int=99)],
            }
        ]
    else:
        base["signals"] = [
            Signal(
                id="behaviour",
                family="suspicious_execution",
                severity="high",
                evidence_ids=[events[0].id],
            )
        ]
    base.update(extra)
    return RiskInput.model_validate(base)


def points(result: Any) -> dict[str, int]:
    return {component.code: component.points for component in result.components}


@pytest.mark.parametrize(
    "value,confidence,expected",
    [
        ("malicious", None, 5),
        ("malicious", 0, 5),
        ("malicious", 1, 5),
        ("malicious", 79, 5),
        ("malicious", 80, 15),
        ("malicious", 100, 15),
        ("suspicious", None, 0),
        ("suspicious", 0, 0),
        ("suspicious", 49, 0),
        ("suspicious", 50, 8),
        ("suspicious", 100, 8),
        ("clean", None, 0),
        ("clean", 0, 0),
        ("clean", 100, 0),
        ("unknown", None, 0),
        ("unknown", 100, 0),
    ],
)
@pytest.mark.parametrize("ti", [False, True])
def test_reputation_thresholds_and_malicious_floor(
    value: str,
    confidence: int | None,
    expected: int,
    ti: bool,
) -> None:
    data = input_data(ti=ti, contexts=[fact(value, confidence)])
    before = deepcopy(data.model_dump(mode="json"))
    result = v4.calculate(data)
    assert points(result)["I"] == expected
    assert result.score == (30 if ti else 45) + expected
    assert result.level == ("high" if result.score >= 60 else "medium")
    assert result.confidence_status == "unknown"
    assert data.model_dump(mode="json") == before
    context = next(item for item in result.components if item.code == "I")
    assert context.status == "known"
    assert context.evidence_ids == ([UUID(int=1)] if expected else [])


def test_malicious_floor_is_versioned_and_does_not_change_v3_hash_or_scores() -> None:
    data = input_data(contexts=[fact("malicious", None)])
    assert v3.calculate(data).score == 45
    assert v4.calculate(data).score == 50
    assert v3.POLICY_VERSION == "risk-policy-v3"
    assert v3.POLICY_HASH == "c31345e2ddf0c7db506791465d20ebcc0e0e6f92e2fc7d1fb0653465f5ee4b94"
    assert v4.POLICY_VERSION == "risk-policy-v4" and v4.POLICY_HASH != v3.POLICY_HASH


def test_duplicated_and_overlapping_ioc_facts_use_maximum_without_summing() -> None:
    facts = [fact("malicious", None), fact("malicious", 80), fact("suspicious", 100)]
    for ordering in permutations(facts):
        data = input_data(contexts=[*ordering, *ordering])
        result = v4.calculate(data)
        assert result.score == 60 and points(result)["I"] == 15
        assert next(item for item in result.components if item.code == "I").evidence_ids == [
            UUID(int=1)
        ]


@pytest.mark.parametrize(
    "context",
    [
        {"active": False},
        {"expires_at": START},
        {"expires_at": START - timedelta(microseconds=1)},
        {"subject_key": "other-subject"},
        {"evidence_ids": [UUID(int=2)]},
        {"evidence_ids": [UUID(int=1), UUID(int=2)]},
    ],
)
def test_unqualified_inactive_expired_or_foreign_subject_fact_has_no_floor(
    context: dict[str, Any],
) -> None:
    result = v4.calculate(input_data(count=2, contexts=[fact(**context)], subject_keys=["subject"]))
    assert result.score == 45 and points(result)["I"] == 0


@pytest.mark.parametrize(
    "expires,expected",
    [
        (START + timedelta(hours=12), 0),
        (START + timedelta(days=1), 0),
        (START + timedelta(days=1, microseconds=1), 5),
        (None, 5),
    ],
)
def test_expiry_uses_later_of_event_start_and_context_asof(
    expires: datetime | None, expected: int
) -> None:
    provenance = PROVENANCE.model_copy(update={"as_of": START + timedelta(days=1)})
    data = input_data(contexts=[fact(provenance=provenance, expires_at=expires)])
    assert points(v4.calculate(data))["I"] == expected


def test_expiry_ignores_timestamp_of_unqualified_reference() -> None:
    data = input_data(count=2, contexts=[fact(expires_at=START - timedelta(seconds=1))])
    old = data.evidence[1].model_copy(update={"timestamp": START - timedelta(days=7)})
    data = data.model_copy(update={"evidence": [data.evidence[0], old]})
    assert points(v4.calculate(data))["I"] == 0


def test_matching_subject_qualifies_and_unrelated_clean_does_not_cancel_malicious() -> None:
    data = input_data(
        contexts=[fact(subject_key="subject", confidence=80), fact("clean", 100)],
        subject_keys=["subject"],
    )
    assert points(v4.calculate(data))["I"] == 15


def test_no_qualifying_proof_has_no_ioc_points_or_detection_confidence() -> None:
    data = RiskInput(evidence=evidence(3), contexts=[fact(confidence=100)])
    result = v4.calculate(data)
    assert result.score == 0 and result.confidence_status == "not_applicable"
    assert all(item.status == "not_applicable" for item in result.components)


def test_known_context_without_match_has_zero_known_i_and_unchanged_behaviour_points() -> None:
    data = input_data(known_contexts=["ioc_reputation"])
    result = v4.calculate(data)
    component = next(item for item in result.components if item.code == "I")
    assert component.points == 0 and component.status == "known"
    assert result.score == 45 and "ioc_reputation" not in result.missing_contexts


@pytest.mark.parametrize(
    "severity,expected",
    [("informational", 5), ("low", 15), ("medium", 30), ("high", 45), ("critical", 55)],
)
def test_inputs_without_intelligence_keep_exact_v3_result(severity: str, expected: int) -> None:
    data = input_data(
        signals=[
            Signal(
                id="existing",
                family="suspicious_execution",
                severity=severity,
                evidence_ids=[UUID(int=1)],
            )
        ]
    )
    assert v4.uses_intelligence(data) is False
    result = v4.calculate(data)
    assert result.score == expected
    assert canonical_json(result.model_dump(mode="json")) == canonical_json(
        v3.calculate(data).model_dump(mode="json")
    )


def test_existing_sigma_severity_and_other_context_stay_byte_identical_to_v3() -> None:
    data = RiskInput(
        evidence=evidence(1),
        severity_baselines=[
            {"id": "sigma-revision", "severity": "high", "evidence_ids": [UUID(int=1)]}
        ],
        contexts=[
            ContextFact(
                kind="host_criticality",
                value="critical",
                subject_key="host",
                evidence_ids=[UUID(int=1)],
                provenance=PROVENANCE,
            )
        ],
        subject_keys=["host"],
    )
    assert v4.uses_intelligence(data) is False
    assert canonical_json(v4.calculate(data).model_dump(mode="json")) == canonical_json(
        v3.calculate(data).model_dump(mode="json")
    )
    assert v4.calculate(data).score == 60


def test_ti_only_medium_does_not_add_behaviour_units_or_event_bonus() -> None:
    data = input_data(
        ti=True,
        count=8,
        severity_baselines=[
            {
                "id": f"{UUID(int=99 + index)}:intelligence-severity",
                "severity": "medium",
                "evidence_ids": [UUID(int=index + 1)],
            }
            for index in range(8)
        ],
    )
    result = v4.calculate(data)
    assert points(result) == {
        "D": 30,
        "C": 0,
        "E": 0,
        "A": 0,
        "U": 0,
        "I": 0,
        "T": 0,
        "H": 0,
        "P": 0,
    }
    assert (
        result.score == 30 and result.signal_units == [] and result.confidence_status == "unknown"
    )
    for item in result.components:
        if item.code in {"D", "C", "E"}:
            assert "TI" in item.reason and "Sigma" not in item.reason
    assert "detection_confidence" in result.missing_contexts


@pytest.mark.parametrize("severity", ["informational", "low", "high", "critical"])
def test_invalid_ti_baseline_severity_fails_closed(severity: str) -> None:
    data = input_data(
        ti=True,
        severity_baselines=[
            {
                "id": f"{UUID(int=99)}:intelligence-severity",
                "severity": severity,
                "evidence_ids": [UUID(int=1)],
            }
        ],
    )
    with pytest.raises(ValueError, match="intelligence severity must be medium"):
        v4.calculate(data)


def test_mixed_sigma_and_ti_preserves_sigma_winner_and_zero_behaviour_bonus() -> None:
    data = input_data(
        ti=True,
        severity_baselines=[
            {"id": "sigma-revision", "severity": "high", "evidence_ids": [UUID(int=1)]},
            {
                "id": f"{UUID(int=99)}:intelligence-severity",
                "severity": "medium",
                "evidence_ids": [UUID(int=1)],
            },
        ],
    )
    result = v4.calculate(data)
    assert result.score == 45 and points(result)["C"] == points(result)["E"] == 0
    for item in result.components:
        if item.code == "D":
            assert "Sigma" in item.reason
        if item.code in {"C", "E"}:
            assert "TI" in item.reason and "Sigma" in item.reason


def test_mixed_behaviour_and_ti_cites_only_behaviour_for_c_and_e() -> None:
    data = input_data(
        ti=True,
        count=8,
        signals=[
            Signal(
                id="behaviour",
                family="suspicious_execution",
                severity="high",
                evidence_ids=[UUID(int=2), UUID(int=3)],
            )
        ],
        contexts=[fact(confidence=80)],
    )
    result = v4.calculate(data)
    assert points(result)["D"] == 45 and points(result)["C"] == 0 and points(result)["E"] == 2
    assert points(result)["I"] == 15 and result.score == 62 and result.level == "high"
    assert len(result.signal_units) == 1
    event_component = next(item for item in result.components if item.code == "E")
    assert event_component.evidence_ids == [UUID(int=2), UUID(int=3)]


def test_i_override_recalculates_raw_clipping_and_keeps_other_components() -> None:
    events = evidence(8)
    families = [
        "authentication_attack",
        "suspicious_execution",
        "privilege_change",
        "account_change",
    ]
    signals = [
        Signal.model_validate(
            {
                "id": str(index),
                "family": family,
                "severity": "critical",
                "evidence_ids": [events[index].id, events[index + 4].id],
            }
        )
        for index, family in enumerate(families)
    ]
    data = input_data(
        count=8,
        signals=signals,
        contexts=[
            fact(),
            ContextFact(
                kind="host_criticality",
                value="critical",
                evidence_ids=[UUID(int=1)],
                subject_key="host",
                provenance=PROVENANCE,
            ),
            ContextFact(
                kind="user_importance",
                value="critical",
                evidence_ids=[UUID(int=1)],
                subject_key="user",
                provenance=PROVENANCE,
            ),
        ],
        subject_keys=["host", "user"],
    )
    before = v3.calculate(data)
    result = v4.calculate(data)
    assert before.raw_score == 101 and before.clipping == -1
    assert result.raw_score == 106 and result.score == 100 and result.clipping == -6
    assert result.level == "critical"
    for component in before.components:
        if component.code != "I":
            assert (
                component.model_dump()
                == next(
                    item for item in result.components if item.code == component.code
                ).model_dump()
            )


@pytest.mark.parametrize(
    "params",
    [
        {"mode": "replay"},
        {"mode": "replay", "dataset_id": UUID(int=1), "run_id": UUID(int=0)},
        {"mode": "live", "dataset_id": UUID(int=1)},
        {"mode": "live", "run_id": UUID(int=1)},
    ],
)
def test_ambiguous_live_replay_scope_cannot_enter_v4_engine(params: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        input_data(contexts=[fact()], **params)


def test_valid_replay_reputation_keeps_exact_scope_and_same_priority_arithmetic() -> None:
    data = input_data(
        ti=True, contexts=[fact()], mode="replay", dataset_id=UUID(int=9), run_id=UUID(int=10)
    )
    before = data.model_dump(mode="json")
    assert v4.calculate(data).score == 35
    assert data.model_dump(mode="json") == before


def test_intelligence_policy_selection_covers_context_known_context_and_ti_suffix() -> None:
    assert not v4.uses_intelligence(input_data())
    assert not v4.uses_intelligence(RiskInput())
    assert v4.uses_intelligence(input_data(contexts=[fact(active=False)]))
    assert v4.uses_intelligence(input_data(known_contexts=["ioc_reputation"]))
    assert v4.uses_intelligence(input_data(ti=True))


def test_policy_metadata_is_immutable_copy_and_reports_truthful_v3_fallback() -> None:
    view = v4.policy_view()
    assert view["production_default_policy_version"] == "risk-policy-v3"
    assert view["fallback_policy_hash"] == v3.POLICY_HASH
    assert view["ioc_missing_confidence_points"]["malicious"] == 5
    assert view["hash"] == v4.POLICY_HASH
    view["ioc_thresholds"]["malicious"][1] = 99
    view["severity_points"]["high"] = 99
    assert v4.policy_view()["ioc_thresholds"]["malicious"] == [80, 15]
    assert v3.policy_view()["severity_points"]["high"] == 45
