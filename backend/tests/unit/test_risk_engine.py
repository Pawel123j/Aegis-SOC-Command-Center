"""Hand-calculated golden vectors for the versioned integer priority policy."""

from datetime import UTC, datetime, timedelta
from itertools import permutations
from uuid import UUID

import pytest

from app.modules.risk.engine import calculate, policy_view, risk_level
from app.modules.risk.schemas import ContextFact, EvidenceReference, Provenance, RiskInput, Signal

START = datetime(2026, 10, 1, 12, tzinfo=UTC)
PROVENANCE = Provenance(
    source="golden-fixture", version="1", snapshot_sha256="a" * 64, as_of=START - timedelta(days=1)
)


def evidence(count: int) -> list[EvidenceReference]:
    return [
        EvidenceReference(
            id=UUID(int=index + 1), timestamp=START + timedelta(seconds=index), sha256="b" * 64
        )
        for index in range(count)
    ]


def signal(identity: str, ids: list[UUID], **values: object) -> Signal:
    return Signal.model_validate(
        {
            "id": identity,
            "family": "suspicious_execution",
            "severity": "high",
            "evidence_ids": ids,
            **values,
        }
    )


@pytest.mark.parametrize(
    "score,level",
    [
        (0, "low"),
        (29, "low"),
        (30, "medium"),
        (59, "medium"),
        (60, "high"),
        (79, "high"),
        (80, "critical"),
        (100, "critical"),
    ],
)
def test_exact_level_boundaries(score: int, level: str) -> None:
    assert risk_level(score) == level


@pytest.mark.parametrize(
    "severity,points",
    [("informational", 5), ("low", 15), ("medium", 30), ("high", 45), ("critical", 55)],
)
def test_unknown_confidence_uses_explicit_severity_baseline(severity: str, points: int) -> None:
    events = evidence(1)
    result = calculate(
        RiskInput(evidence=events, signals=[signal("a", [events[0].id], severity=severity)])
    )
    assert result.score == points
    assert result.confidence_status == "unknown"
    assert "detection_confidence" in result.missing_contexts
    assert (
        next(part for part in result.components if part.code == "D").details["confidence"] is None
    )


@pytest.mark.parametrize(
    "confidence,points", [(0, 0), (1, 0), (20, 11), (80, 44), (99, 54), (100, 55)]
)
def test_integer_floor_once(confidence: int, points: int) -> None:
    events = evidence(1)
    result = calculate(
        RiskInput(
            evidence=events,
            signals=[
                signal(
                    "a",
                    [events[0].id],
                    severity="critical",
                    confidence=confidence,
                    confidence_provenance=PROVENANCE,
                )
            ],
        )
    )
    assert result.score == points


def test_maximum_keeps_severity_and_confidence_from_the_same_signal() -> None:
    events = evidence(1)
    signals = [
        signal(
            "a",
            [events[0].id],
            severity="critical",
            confidence=20,
            confidence_provenance=PROVENANCE,
        ),
        signal(
            "b", [events[0].id], severity="medium", confidence=100, confidence_provenance=PROVENANCE
        ),
    ]
    result = calculate(RiskInput(evidence=events, signals=signals))
    assert result.score == 30 and len(result.signal_units) == 1


def test_transitive_overlap_and_reordered_inputs_do_not_inflate() -> None:
    events = evidence(4)
    signals = [
        signal("a", [events[0].id, events[1].id]),
        signal("b", [events[2].id, events[3].id]),
        signal("bridge", [events[1].id, events[2].id]),
    ]
    expected = calculate(RiskInput(evidence=events, signals=signals)).model_dump()
    assert expected["score"] == 51
    for ordering in permutations(signals):
        assert (
            calculate(
                RiskInput(evidence=list(reversed(events)), signals=[*ordering, ordering[0]])
            ).model_dump()
            == expected
        )


@pytest.mark.parametrize("count,score", [(1, 45), (2, 50), (3, 55), (4, 60), (5, 62), (8, 66)])
def test_independent_signals_and_event_caps(count: int, score: int) -> None:
    events = evidence(count)
    result = calculate(
        RiskInput(
            evidence=events,
            signals=[signal(str(index), [event.id]) for index, event in enumerate(events)],
        )
    )
    assert result.score == score


def test_three_behavior_chain_uses_maximum_detection_not_score_sums() -> None:
    events = evidence(9)
    signals = [
        signal(
            "authentication",
            [item.id for item in events[:6]],
            family="authentication_attack",
            severity="critical",
        ),
        signal("execution", [events[6].id, events[8].id], severity="critical"),
        signal("privilege", [events[7].id], family="privilege_change", severity="critical"),
    ]
    result = calculate(RiskInput(evidence=events, signals=signals))
    assert result.score == 73
    assert {part.code: part.points for part in result.components} == {
        "D": 55,
        "C": 6,
        "E": 12,
        "A": 0,
        "U": 0,
        "I": 0,
        "T": 0,
        "H": 0,
        "P": 0,
    }


def test_maximum_context_vector_clips_raw132_to100() -> None:
    events = evidence(8)
    families = [
        "authentication_attack",
        "suspicious_execution",
        "privilege_change",
        "account_change",
    ]
    signals = [
        signal(
            str(index), [events[index].id, events[index + 4].id], family=family, severity="critical"
        )
        for index, family in enumerate(families)
    ]
    facts = [
        ContextFact(
            kind="host_criticality",
            value="critical",
            subject_key="host:1",
            evidence_ids=[events[0].id],
            provenance=PROVENANCE,
        ),
        ContextFact(
            kind="user_importance",
            value="critical",
            subject_key="user:1",
            evidence_ids=[events[0].id],
            provenance=PROVENANCE,
        ),
        ContextFact(
            kind="ioc_reputation",
            value="malicious",
            confidence=80,
            evidence_ids=[events[0].id],
            provenance=PROVENANCE,
        ),
        ContextFact(
            kind="prior_privileges",
            value="administrator",
            subject_key="user:1",
            observed_at=START - timedelta(days=1),
            evidence_ids=[events[0].id],
            provenance=PROVENANCE,
        ),
        ContextFact(
            kind="confirmed_history",
            value="confirmed_malicious",
            subject_key="user:1",
            observed_at=START - timedelta(days=2),
            evidence_ids=[events[0].id],
            prior_incident_id=UUID(int=99),
            prior_evidence_ids=[UUID(int=98)],
            prior_mode="live",
            prior_run_id=UUID(int=0),
            provenance=PROVENANCE,
        ),
        *[
            ContextFact(
                kind="attack_tactics",
                value=f"TA000{index + 1}",
                evidence_ids=[events[index].id],
                provenance=PROVENANCE,
            )
            for index in range(4)
        ],
    ]
    result = calculate(
        RiskInput(
            evidence=events, signals=signals, contexts=facts, subject_keys=["host:1", "user:1"]
        )
    )
    assert result.raw_score == 132 and result.score == 100 and result.clipping == -32
    assert result.missing_contexts == ["detection_confidence"]


@pytest.mark.parametrize(
    "kind,weights",
    [
        ("host_criticality", {"low": 0, "medium": 5, "high": 10, "critical": 15}),
        ("user_importance", {"low": 0, "medium": 3, "high": 6, "critical": 10}),
        ("prior_privileges", {"standard": 0, "privileged": 3, "administrator": 5}),
    ],
)
def test_all_context_weight_cells(kind: str, weights: dict[str, int]) -> None:
    events = evidence(1)
    for value, points in weights.items():
        fact = ContextFact.model_validate(
            {
                "kind": kind,
                "value": value,
                "subject_key": "subject:1",
                "evidence_ids": [events[0].id],
                "observed_at": START - timedelta(days=1),
                "provenance": PROVENANCE,
            }
        )
        result = calculate(
            RiskInput(
                evidence=events,
                signals=[signal("a", [events[0].id])],
                contexts=[fact],
                subject_keys=["subject:1"],
            )
        )
        assert result.score == 45 + points


def test_empty_and_unreferenced_inputs_produce_no_points() -> None:
    result = calculate(RiskInput(evidence=evidence(8)))
    assert result.score == 0 and all(part.status == "not_applicable" for part in result.components)


def test_policy_metadata_cannot_mutate_global_weights() -> None:
    view = policy_view()
    view["severity_points"]["high"] = 100
    assert policy_view()["severity_points"]["high"] == 45
