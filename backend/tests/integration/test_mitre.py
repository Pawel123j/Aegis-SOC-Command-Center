"""Real atomic worker associations, old-data preservation and deployment coverage."""

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.modules.alerts.models import Alert
from app.modules.correlation.processing import process_once as correlate_once
from app.modules.incidents.models import Incident
from app.modules.mitre.catalogue import CATALOGUE_SHA256
from app.modules.mitre.models import AlertMitreMapping, AlertMitreSnapshot
from app.modules.risk.models import RiskCalculation

from .helper_correlation import auth_sequence, normalize_inputs, seal
from .helper_ingestion import processing_database
from .helpers import Case, Login, migrate
from .test_incidents import create
from .test_initial_alerts import alerts, detect_once, normalize_events, powershell

pytestmark = pytest.mark.integration


def coverage(admin: Login, **params: Any) -> dict[str, Any]:
    response = admin.client.get(
        "/api/v1/mitre/coverage",
        params={"from": "2026-10-01T00:00:00Z", "to": "2026-10-02T00:00:00Z", **params},
        headers=admin.authorization,
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    return response.json()  # type: ignore[no-any-return]


def test_worker_persists_frozen_candidate_mapping_in_alert_and_case_without_risk_t_claims(
    case: Case, admin: Login
) -> None:
    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    record = alerts(case)[0]
    original = deepcopy(record.rule_snapshot)
    with Session(case.database.runtime) as db:
        snapshot = db.get(AlertMitreSnapshot, record.id)
        assert snapshot is not None and snapshot.catalogue_hash == CATALOGUE_SHA256
        assert snapshot.document["techniques"][0]["name"] == "PowerShell"
        assert db.scalar(select(func.count()).select_from(AlertMitreMapping)) == 1
        risk = db.get(RiskCalculation, record.risk_calculation_id)
        assert risk is not None
        assert (
            next(item for item in risk.explanation["components"] if item["code"] == "T")["status"]
            == "unknown"
        )
        incident = db.scalar(select(Incident).where(Incident.automatic_alert_id == record.id))
        assert incident is not None
        identifier = incident.id
    detail = admin.client.get(f"/api/v1/alerts/{record.id}", headers=admin.authorization).json()
    assert detail["rule_snapshot"] == original
    assert detail["risk_score"] == 45
    view = detail["mitre_mapping"]
    assert view["status"] == "mapped" and view["confirmed_attack"] is False
    assert view["claim"] == "candidate_association" and view["catalogue_version"] == "19.2"
    assert view["techniques"][0]["tactics"] == [
        {"id": "TA0002", "name": "Execution", "url": "https://attack.mitre.org/tactics/TA0002"}
    ]
    case_detail = admin.client.get(
        f"/api/v1/incidents/{identifier}", headers=admin.authorization
    ).json()
    assert case_detail["mitre_mapping"]["mapped_alerts"] == 1
    assert case_detail["mitre_mapping"]["techniques"][0]["catalogue_hash"] == CATALOGUE_SHA256
    assert record.rule_snapshot == original


def test_linux_root_session_remains_explicitly_unmapped_in_every_view(
    case: Case, admin: Login
) -> None:
    normalize_events(
        case,
        admin,
        [
            {
                "source_type": "linux_auth",
                "timestamp": "2026-10-01T12:00:00Z",
                "raw_event": "Oct  1 12:00:00 host sudo[1]: alice : TTY=pts/0 ; "
                "PWD=/home/alice ; USER=root ; COMMAND=/bin/bash -i",
            }
        ],
    )
    detect_once(processing_database(case), case.database.settings)
    record = alerts(case)[0]
    view = admin.client.get(f"/api/v1/alerts/{record.id}", headers=admin.authorization).json()[
        "mitre_mapping"
    ]
    assert view["status"] == "unmapped" and view["techniques"] == []
    incident = create(admin, alert_ids=[str(record.id)])
    assert incident["mitre_mapping"]["unmapped_alerts"] == 1
    result = coverage(admin)
    assert result["summary"]["unmapped_alerts"] == 1
    assert result["summary"]["mapped_alerts"] == result["summary"]["observed_techniques"] == 0
    assert result["summary"]["incidents"] == 1
    definition = admin.client.get(
        "/api/v1/detections/linux-root-session", headers=admin.authorization
    ).json()
    assert definition["mitre"] == [] and definition["mitre_mapping"]["status"] == "unmapped"


def test_multiple_alerts_in_one_case_do_not_multiply_technique_or_tactic_counts(
    case: Case, admin: Login
) -> None:
    normalize_events(case, admin, [powershell(), powershell()])
    detect_once(processing_database(case), case.database.settings)
    records = alerts(case)
    incident = create(admin, alert_ids=[str(record.id) for record in records])
    assert len(incident["mitre_mapping"]["techniques"]) == 1
    assert incident["mitre_mapping"]["mapped_alerts"] == 2
    result = coverage(admin)
    technique = next(row for row in result["techniques"] if row["id"] == "T1059.001")
    tactic = next(row for row in result["tactics"] if row["id"] == "TA0002")
    assert technique["alert_count"] == tactic["alert_count"] == 2
    assert technique["incident_count"] == tactic["incident_count"] == 3
    assert result["summary"]["eligible_alerts"] == 2
    assert result["summary"]["incidents"] == 3
    assert result["summary"]["observed_techniques"] == 1
    assert result["summary"]["observed_tactics"] == 1
    assert next(row for row in result["techniques"] if row["id"] == "T1059")["alert_count"] == 0


def test_correlated_candidate_accounts_reference_all_official_tactics_without_new_intent(
    case: Case, admin: Login
) -> None:
    scope = (uuid4(), uuid4())
    normalize_inputs(
        case, admin, auth_sequence(datetime(2026, 10, 1, 12, tzinfo=UTC)), replay=scope
    )
    seal(admin, scope, 6)
    correlate_once(processing_database(case), case.database.settings)
    result = coverage(admin, mode="replay", dataset_id=str(scope[0]), run_id=str(scope[1]))
    assert result["summary"]["eligible_alerts"] == 2
    assert result["summary"]["observed_techniques"] == 2
    assert result["summary"]["observed_tactics"] == 5
    technique = next(row for row in result["techniques"] if row["id"] == "T1078")
    assert technique["alert_count"] == technique["incident_count"] == 1
    assert technique["tactic_ids"] == ["TA0001", "TA0003", "TA0004", "TA0005"]
    credential = next(row for row in result["tactics"] if row["id"] == "TA0006")
    assert credential["alert_count"] == 2 and credential["incident_count"] == 1
    assert result["confirmed_attack"] is False


def test_enabled_rule_coverage_is_separate_from_configured_and_observed_history(
    case: Case, admin: Login
) -> None:
    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    prior = coverage(admin)
    for route, rule_id in (
        ("detections", "powershell-suspicious-command"),
        ("correlations", "powershell_then_outbound"),
        ("correlations", "possible_multi_stage_compromise"),
    ):
        response = admin.client.patch(
            f"/api/v1/{route}/{rule_id}",
            json={"enabled": False},
            headers={**admin.authorization, "If-Match": '"1"'},
        )
        assert response.status_code == 200, response.text
    after = coverage(admin)
    original = next(row for row in prior["techniques"] if row["id"] == "T1059.001")
    current = next(row for row in after["techniques"] if row["id"] == "T1059.001")
    assert original["configured_rule_count"] == original["enabled_rule_count"] == 3
    assert current["configured_rule_count"] == 3 and current["enabled_rule_count"] == 0
    assert original["alert_count"] == current["alert_count"] == 1
    assert original["incident_count"] == current["incident_count"] == 1


def test_retries_restarts_and_gets_do_not_duplicate_or_write_frozen_associations(
    case: Case, admin: Login
) -> None:
    normalize_events(case, admin, [powershell()])
    database = processing_database(case)
    detect_once(database, case.database.settings)
    record = alerts(case)[0]
    with Session(case.database.runtime) as db:
        original = db.get(AlertMitreSnapshot, record.id)
        assert original is not None
        frozen = deepcopy(original.document)
    for _ in range(2):
        detect_once(processing_database(case), case.database.settings)
        assert coverage(admin)["summary"]["mapped_alerts"] == 1
        response = admin.client.get("/api/v1/mitre/catalog", headers=admin.authorization)
        assert response.status_code == 200 and len(response.json()["techniques"]) == 697
    with Session(case.database.runtime) as db:
        assert db.scalar(select(func.count()).select_from(AlertMitreSnapshot)) == 1
        assert db.scalar(select(func.count()).select_from(AlertMitreMapping)) == 1
        assert db.get(AlertMitreSnapshot, record.id).document == frozen  # type: ignore[union-attr]


def test_additive_migration_keeps_legacy_alert_and_risk_history_byte_identical(
    case: Case, admin: Login
) -> None:
    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    record = alerts(case)[0]
    with Session(case.database.runtime) as db:
        risk = db.get(RiskCalculation, record.risk_calculation_id)
        assert risk is not None
        original_risk = deepcopy(risk.explanation)
        original_snapshot = deepcopy(record.rule_snapshot)
    # Owner-only fixture reconstructs a pre-stage database, within this generated test DB.
    assert case.database.name.startswith("aegis_test_")
    with case.database.owner.begin() as db:
        db.execute(text("DELETE FROM alert_mitre_mappings"))
        db.execute(text("DELETE FROM alert_mitre_snapshots"))
    migrate(case.database.owner, "0007_risk", downgrade=True)
    migrate(case.database.owner)
    response = admin.client.get(f"/api/v1/alerts/{record.id}", headers=admin.authorization)
    assert response.status_code == 200
    assert response.json()["mitre_mapping"]["status"] == "legacy_unmapped"
    assert response.json()["rule_snapshot"] == original_snapshot
    assert response.json()["risk_explanation"]["score"] == 45
    with Session(case.database.runtime) as db:
        assert db.get(RiskCalculation, record.risk_calculation_id).explanation == original_risk  # type: ignore[union-attr]
        assert db.scalar(select(func.count()).select_from(AlertMitreSnapshot)) == 0
    assert coverage(admin)["summary"]["legacy_alerts"] == 1


def test_mapping_insert_failure_rolls_back_alert_risk_case_audit_and_job(
    case: Case, admin: Login
) -> None:
    normalize_events(case, admin, [powershell()])
    with case.database.owner.begin() as db:
        db.execute(text("REVOKE INSERT ON alert_mitre_snapshots FROM aegis_app"))
    try:
        from sqlalchemy.exc import DBAPIError

        with pytest.raises(DBAPIError):
            detect_once(processing_database(case), case.database.settings)
    finally:
        with case.database.owner.begin() as db:
            db.execute(text("GRANT INSERT ON alert_mitre_snapshots TO aegis_app"))
    with Session(case.database.runtime) as db:
        for model in (Alert, RiskCalculation, Incident, AlertMitreSnapshot, AlertMitreMapping):
            assert db.scalar(select(func.count()).select_from(model)) == 0
        assert db.scalar(text("SELECT count(*) FROM detection_jobs WHERE state='pending'")) == 1
        assert db.scalar(text("SELECT count(*) FROM audit_logs WHERE action='alert.created'")) == 0
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 1
