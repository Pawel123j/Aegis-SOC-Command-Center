"""Real durable scoring, historical replay and safe additive schema migration."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.modules.alerts.models import Alert
from app.modules.correlation.processing import process_once as correlate_once
from app.modules.incidents.models import Incident
from app.modules.risk.engine import calculate
from app.modules.risk.models import RiskCalculation
from app.modules.risk.schemas import RiskInput

from .helper_correlation import auth_sequence, normalize_inputs, seal
from .helper_ingestion import processing_database
from .helpers import Case, Login, migrate
from .test_initial_alerts import alerts, detect_once, normalize_events, powershell

pytestmark = pytest.mark.integration


def test_new_alert_and_automatic_case_have_reproducible_distinct_assessments(
    case: Case, admin: Login
) -> None:
    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    alert = alerts(case)[0]
    with Session(case.database.runtime) as db:
        incident = db.scalar(select(Incident).where(Incident.automatic_alert_id == alert.id))
        assert incident is not None and incident.risk_score == alert.risk_score == 45
        assert incident.risk_calculation_id != alert.risk_calculation_id
        for subject in (alert, incident):
            row = db.get(RiskCalculation, subject.risk_calculation_id)
            assert row is not None
            reproduced = calculate(RiskInput.model_validate(row.input_snapshot["scoring_input"]))
            assert reproduced.model_dump(mode="json") == row.explanation
    detail = admin.client.get(f"/api/v1/alerts/{alert.id}", headers=admin.authorization).json()
    assert detail["risk_explanation"]["policy_version"] == "risk-policy-v3"
    assert detail["risk_explanation"]["confidence_status"] == "unknown"


def test_replay_run_has_frozen_evidence_priority_without_context_claims(
    case: Case, admin: Login
) -> None:
    scope = (uuid4(), uuid4())
    normalize_inputs(case, admin, auth_sequence(datetime(2020, 1, 1, tzinfo=UTC)), replay=scope)
    seal(admin, scope, 6)
    correlate_once(processing_database(case), case.database.settings)
    with Session(case.database.runtime) as db:
        row = db.scalar(select(Alert).where(Alert.rule_id == "possible_bruteforce_compromise"))
        assert row is not None and row.risk_score == 55 and row.risk_level == "medium"
        calculation = db.get(RiskCalculation, row.risk_calculation_id)
        assert calculation is not None and calculation.mode == "replay"
        assert calculation.dataset_id == scope[0] and calculation.run_id == scope[1]
        assert calculation.input_snapshot["context_origin"] == "unknown-context-as-of-replay"


def test_history_reads_are_bounded_and_never_write_scores(case: Case, admin: Login) -> None:
    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    record = alerts(case)[0]
    path = f"/api/v1/alerts/{record.id}/risk"
    first = admin.client.get(path, params={"limit": 1}, headers=admin.authorization)
    second = admin.client.get(path, params={"limit": 1}, headers=admin.authorization)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert first.json()["current"]["id"] == str(record.risk_calculation_id)
    assert len(first.json()["history"]) == 1 and not first.json()["history_truncated"]
    assert (
        admin.client.get(path, params={"limit": 51}, headers=admin.authorization).status_code == 422
    )
    assert (
        admin.client.get(
            f"/api/v1/alerts/{UUID(int=999)}/risk", headers=admin.authorization
        ).status_code
        == 404
    )


def test_downgrade_refuses_to_destroy_existing_risk_history(
    case: Case,
    admin: Login,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migrate(case.database.owner, "0010_entities", downgrade=True)
    migrate(case.database.owner, "0009_sigma", downgrade=True)
    with monkeypatch.context() as patch:
        patch.setattr("app.modules.normalization.processing.index_event", lambda *_: None)
        patch.setattr("app.modules.detections.processing.index_alert", lambda *_: None)
        patch.setattr(
            "app.modules.detections.processing._intelligence_evaluation", lambda *_: (None, None)
        )
        patch.setattr("app.modules.risk.inputs.risk_contexts", lambda *_: ([], {}))
        # Keep MITRE empty so that the rejection proves the older risk guard itself.
        patch.setattr("app.modules.detections.processing.record_mapping", lambda *_: None)
        normalize_events(case, admin, [powershell()])
        detect_once(processing_database(case), case.database.settings)
    record = alerts(case)[0]
    with pytest.raises(DBAPIError) as rejected:
        migrate(case.database.owner, "0006_correlation", downgrade=True)
    assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
    assert "risk history exists" in str(rejected.value)
    with case.database.runtime.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "0009_sigma"
        assert db.scalar(text("SELECT count(*) FROM risk_calculations")) == 2
    migrate(case.database.owner)
    with case.database.runtime.connect() as db:
        assert db.scalar(text("SELECT count(*) FROM risk_calculations")) == 2
    assert alerts(case)[0].risk_calculation_id == record.risk_calculation_id
