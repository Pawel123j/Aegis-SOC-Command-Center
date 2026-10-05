"""Independent validation of existing risk evidence used by entity projections."""

import hashlib
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from app.core.errors import ApiError
from app.modules.entities import views
from app.modules.ingestion.schemas import canonical_json
from app.modules.risk import engine
from app.modules.risk.schemas import EvidenceReference, RiskInput, Signal

NOW = datetime(2026, 10, 4, 12, tzinfo=UTC)
ALERT = UUID(int=1)
EVENT = UUID(int=2)
CALCULATION = UUID(int=3)


def projection(*, replay: bool = False) -> dict[str, Any]:
    """An existing, independently scored alert with its complete original proof."""
    dataset = UUID(int=4) if replay else None
    run = UUID(int=5) if replay else UUID(int=0)
    scoring = RiskInput(
        evidence=[EvidenceReference(id=EVENT, timestamp=NOW, sha256="a" * 64)],
        signals=[
            Signal(
                id="powershell-suspicious-command",
                family="suspicious_execution",
                severity="high",
                evidence_ids=[EVENT],
                alert_ids=[ALERT],
            )
        ],
        subject_id=ALERT,
        mode="replay" if replay else "live",
        dataset_id=dataset,
        run_id=run,
    )
    result = engine.calculate(scoring)
    source = {
        "id": str(ALERT),
        "event_sha256": "a" * 64,
        "rule_id": "powershell-suspicious-command",
        "rule_version": "1.0.0",
        "evaluator_version": "builtin-v1",
        "severity": "high",
    }
    snapshot = {
        "scoring_input": scoring.model_dump(mode="json"),
        "source_alerts": [deepcopy(source)],
        "excluded_alert_ids": [],
    }
    definition = {
        "id": str(CALCULATION),
        "subject_type": "alert",
        "subject_id": str(ALERT),
        "subject_revision": 1,
        "created_at": NOW.isoformat(),
        "actor_id": None,
        "trigger": "evidence_changed",
        "previous_id": None,
        "policy_version": engine.POLICY_VERSION,
        "policy_hash": engine.POLICY_HASH,
        "input_sha256": hashlib.sha256(canonical_json(snapshot)).hexdigest(),
        "input_snapshot": snapshot,
        "explanation": result.model_dump(mode="json"),
        "score": result.score,
        "level": result.level,
        "mode": scoring.mode,
        # Live alert rows retain the source dataset; live scoring has no dataset.
        "dataset_id": str(dataset) if dataset else str(UUID(int=6)),
        "run_id": str(run),
    }
    return {
        "counts": {"eligible_alerts": 1, "false_positive_alerts": 0},
        "assessed_alerts": 1,
        "invalid_risk": 0,
        "identity": {
            "mode": scoring.mode,
            "dataset_id": str(dataset) if dataset else None,
            "run_id": str(run),
        },
        "risk": {
            "calculation": definition,
            "alert_id": str(ALERT),
            "source": source,
            "proof": [{"event_id": str(EVENT), "sha256": "a" * 64, "timestamp": NOW.isoformat()}],
        },
    }


def rehash(raw: dict[str, Any]) -> None:
    row = raw["risk"]["calculation"]
    row["input_sha256"] = hashlib.sha256(canonical_json(row["input_snapshot"])).hexdigest()


@pytest.mark.parametrize("replay", [False, True])
def test_projection_returns_existing_calculation_without_new_entity_score(replay: bool) -> None:
    raw = projection(replay=replay)
    before = deepcopy(raw)
    result = views.risk(raw)
    assert result.score == 45 and result.level == "medium"
    assert result.alert_id == ALERT and result.calculation_id == CALCULATION
    assert result.entity_calculation is False
    assert result.strategy == "maximum_current_eligible_alert"
    assert result.policy_version == engine.POLICY_VERSION
    assert result.explanation is not None
    assert result.explanation["input_snapshot"] == raw["risk"]["calculation"]["input_snapshot"]
    assert raw == before


def test_historical_v2_projection_is_read_without_recalculation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = projection()
    row = raw["risk"]["calculation"]
    row["policy_version"] = "risk-policy-v2"
    row["policy_hash"] = "fe87d0dd228f33d01ce32434cd8ac6620f4cf1d3723ebd077ca2add7b466e85c"
    del row["input_snapshot"]["scoring_input"]["severity_baselines"]
    rehash(raw)
    before = deepcopy(raw)

    def forbidden_recalculation(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Reading a profile must not calculate risk under today's policy")

    monkeypatch.setattr(engine, "calculate", forbidden_recalculation)
    result = views.risk(raw)
    assert result.score == 45 and result.policy_version == "risk-policy-v2"
    assert raw == before


@pytest.mark.parametrize(
    "change",
    [
        "input_hash",
        "policy_hash",
        "policy_version",
        "subject_type",
        "subject_id",
        "mode",
        "run_id",
        "dataset_id",
        "proof_hash",
        "proof_timestamp",
        "proof_missing",
        "proof_duplicate",
        "source_severity",
        "source_missing",
        "excluded_alert",
        "scoring_subject",
        "scoring_timestamp",
        "scoring_scope",
        "explanation_score",
        "explanation_level",
        "inconsistent_current",
    ],
)
def test_projection_rejects_forged_or_inconsistent_existing_evidence(change: str) -> None:
    raw = projection(replay=True)
    candidate = raw["risk"]
    row = candidate["calculation"]
    snapshot = row["input_snapshot"]
    changes = {
        "input_hash": ("input_sha256", "0" * 64),
        "policy_hash": ("policy_hash", "0" * 64),
        "policy_version": ("policy_version", "unknown-policy"),
        "subject_type": ("subject_type", "incident"),
        "subject_id": ("subject_id", str(UUID(int=99))),
        "mode": ("mode", "live"),
        "run_id": ("run_id", str(UUID(int=99))),
        "dataset_id": ("dataset_id", str(UUID(int=99))),
    }
    if change in changes:
        key, value = changes[change]
        row[key] = value
    elif change == "proof_hash":
        candidate["proof"][0]["sha256"] = "0" * 64
    elif change == "proof_timestamp":
        candidate["proof"][0]["timestamp"] = "2026-10-03T12:00:00+00:00"
    elif change == "proof_missing":
        candidate["proof"] = []
    elif change == "proof_duplicate":
        candidate["proof"].append(deepcopy(candidate["proof"][0]))
    elif change == "source_severity":
        snapshot["source_alerts"][0]["severity"] = "critical"
        rehash(raw)
    elif change == "source_missing":
        snapshot["source_alerts"] = []
        rehash(raw)
    elif change == "excluded_alert":
        snapshot["excluded_alert_ids"] = [str(ALERT)]
        rehash(raw)
    elif change == "scoring_subject":
        snapshot["scoring_input"]["subject_id"] = str(UUID(int=99))
        rehash(raw)
    elif change == "scoring_timestamp":
        snapshot["scoring_input"]["evidence"][0]["timestamp"] = "2026-10-03T12:00:00+00:00"
        rehash(raw)
    elif change == "scoring_scope":
        snapshot["scoring_input"]["dataset_id"] = str(UUID(int=99))
        rehash(raw)
    elif change == "explanation_score":
        row["explanation"]["score"] = 90
    elif change == "explanation_level":
        row["explanation"]["level"] = "critical"
    else:
        raw["invalid_risk"] = 1
    with pytest.raises(ApiError) as rejected:
        views.risk(raw)
    assert rejected.value.status == 409
    assert rejected.value.code == "entity_risk_integrity_mismatch"


def test_unassessed_or_excluded_activity_does_not_invent_zero_risk() -> None:
    raw = projection()
    raw.update(risk=None, assessed_alerts=0)
    raw["counts"]["false_positive_alerts"] = 4
    result = views.risk(raw)
    assert result.score is None and result.level is None and result.calculation_id is None
    assert result.excluded_false_positive_alerts == 4
    assert result.eligible_alerts == 1 and result.assessed_alerts == 0


@pytest.mark.parametrize("events,alerts,complete", [(0, 0, True), (1, 0, False), (0, 1, False)])
def test_index_completeness_requires_both_event_and_alert_receipts(
    events: int,
    alerts: int,
    complete: bool,
) -> None:
    result = views.status({"pending_events": events, "pending_alerts": alerts})
    assert result.complete is complete
