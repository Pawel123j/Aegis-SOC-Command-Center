"""Real ingestion-to-IOC proof, immutable revisions, priority and atomic rollback."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.modules.detections.models import DetectionJob
from app.modules.detections.processing import process_once as detect_once
from app.modules.intelligence import matching
from app.modules.intelligence.contracts import RULE_ID
from app.modules.intelligence.models import IntEventMatch, IntEventReceipt
from app.modules.normalization.models import NormalizedEvent
from app.modules.normalization.schemas import NormalizedSecurityEvent
from app.modules.risk.models import RiskCalculation

from .helper_correlation import auth_event, normalize_inputs
from .helper_entities import read as read_entity
from .helper_ingestion import processing_database
from .helpers import Case, Login
from .test_initial_alerts import alerts, normalize_events, powershell

pytestmark = pytest.mark.integration
START = datetime(2026, 10, 1, 12, tzinfo=UTC)


def ioc(admin: Login, kind: str = "ip", value: str = "192.0.2.1", **values: Any) -> dict[str, Any]:
    response = admin.client.post(
        "/api/v1/intelligence/iocs",
        json={
            "type": kind,
            "value": value,
            "source": "reviewed test fixture",
            "reputation": "malicious",
            "confidence": 90,
            **values,
        },
        headers=admin.authorization,
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


def proof(admin: Login, identity: UUID) -> dict[str, Any]:
    response = admin.client.get(
        f"/api/v1/intelligence/events/{identity}", headers=admin.authorization
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


def patch(admin: Login, record: dict[str, Any], **values: Any) -> dict[str, Any]:
    response = admin.client.patch(
        f"/api/v1/intelligence/iocs/{record['id']}",
        json=values,
        headers={**admin.authorization, "If-Match": f'"{record["version"]}"'},
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


def hashed_powershell(digest: str) -> dict[str, Any]:
    event = powershell()
    values = event["raw_event"]["EventData"]
    event["raw_event"]["EventID"] = 1
    event["raw_event"]["ProviderName"] = "Microsoft-Windows-Sysmon"
    event["raw_event"]["EventData"] = {
        "Image": values["NewProcessName"],
        "CommandLine": values["CommandLine"],
        "User": "LAB\\alice",
        "Hashes": "SHA256=" + digest,
    }
    return event


def test_malicious_plain_event_creates_explainable_ti_alert_and_profile_priority(
    case: Case, admin: Login
) -> None:
    record = ioc(admin)
    _, ids = normalize_inputs(case, admin, [auth_event(START)])
    before = proof(admin, ids[0])
    assert before["status"] == "pending" and not before["matches"]
    assert detect_once(processing_database(case), case.database.settings) == {
        "processed": 1,
        "quarantined": 0,
        "alerts": 1,
    }
    rows = alerts(case)
    assert len(rows) == 1 and rows[0].rule_id == RULE_ID and rows[0].risk_score == 45
    response = admin.client.get(f"/api/v1/alerts/{rows[0].id}", headers=admin.authorization)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["detection_type"] == "intelligence" and data["event_count"] == 1
    risk = data["risk_explanation"]
    assert risk["policy_version"] == "risk-policy-v4" and risk["confidence_status"] == "unknown"
    components = {item["code"]: item for item in risk["components"]}
    assert components["D"]["points"] == 30 and components["I"]["points"] == 15
    assert components["C"]["points"] == components["E"]["points"] == 0
    assert "TI" in components["D"]["reason"] and not risk["signal_units"]
    assert data["mitre_mapping"]["status"] == "unmapped"
    assert not data["mitre_mapping"]["confirmed_attack"]
    frozen = proof(admin, ids[0])
    assert frozen["status"] == "evaluated" and frozen["match_count"] == 1
    match = frozen["matches"][0]
    assert match["field"] == "source.ip" and match["revision_id"] == record["revision_id"]
    assert match["revision_snapshot"]["source"] == "reviewed test fixture"
    page = read_entity(admin, kind="ip")
    detail = read_entity(admin, f"/{page['items'][0]['id']}")
    assert detail["risk"]["score"] == 45 and detail["risk"]["policy_version"] == "risk-policy-v4"
    assert proof(admin, ids[0]) == frozen
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 0


@pytest.mark.parametrize("confidence,expected", [(None, 35), (0, 35), (79, 35), (80, 45)])
def test_malicious_reputation_always_increases_priority_with_truthful_confidence(
    case: Case, admin: Login, confidence: int | None, expected: int
) -> None:
    ioc(admin, confidence=confidence)
    _, ids = normalize_inputs(case, admin, [auth_event(START)])
    detect_once(processing_database(case), case.database.settings)
    assert alerts(case)[0].risk_score == expected
    assert proof(admin, ids[0])["matches"][0]["revision_snapshot"]["confidence"] == confidence


def test_catalog_edit_does_not_rewrite_existing_event_alert_or_risk(
    case: Case, admin: Login
) -> None:
    record = ioc(admin)
    _, ids = normalize_inputs(case, admin, [auth_event(START)])
    detect_once(processing_database(case), case.database.settings)
    frozen = proof(admin, ids[0])
    alert = alerts(case)[0]
    first = admin.client.get(f"/api/v1/alerts/{alert.id}/risk", headers=admin.authorization).json()
    changed = patch(admin, record, reputation="clean", active=False, source="retracted source")
    assert changed["revision"] == 2
    assert proof(admin, ids[0]) == frozen
    recalc = admin.client.post(
        f"/api/v1/alerts/{alert.id}/risk/recalculate",
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert recalc.status_code == 200, recalc.text
    assert (
        admin.client.get(f"/api/v1/alerts/{alert.id}/risk", headers=admin.authorization).json()
        == first
    )
    _, later = normalize_inputs(case, admin, [auth_event(START + timedelta(seconds=1))])
    detect_once(processing_database(case), case.database.settings)
    assert proof(admin, later[0])["match_count"] == 0 and len(alerts(case)) == 1


def test_empty_receipt_never_retroactively_adopts_new_ioc(case: Case, admin: Login) -> None:
    _, ids = normalize_inputs(case, admin, [auth_event(START)])
    detect_once(processing_database(case), case.database.settings)
    empty = proof(admin, ids[0])
    assert empty["status"] == "evaluated" and empty["match_count"] == 0
    ioc(admin)
    response = admin.client.post(
        "/api/v1/intelligence/backfill", json={"limit": 100}, headers=admin.authorization
    )
    assert response.status_code == 200 and response.json()["events"] == 0
    assert proof(admin, ids[0]) == empty and not alerts(case)


@pytest.mark.parametrize(
    "reputation,confidence,bonus",
    [("suspicious", 50, 8), ("suspicious", None, 0), ("clean", 100, 0), ("unknown", None, 0)],
)
def test_nonmalicious_ioc_enriches_existing_behaviour_without_inventing_ti_alert(
    case: Case, admin: Login, reputation: str, confidence: int | None, bonus: int
) -> None:
    digest = "a" * 64
    ioc(admin, "hash", digest, reputation=reputation, confidence=confidence)
    event = hashed_powershell(digest)
    ids = normalize_events(case, admin, [event])
    detect_once(processing_database(case), case.database.settings)
    rows = alerts(case)
    assert len(rows) == 1 and rows[0].rule_id == "powershell-suspicious-command"
    assert rows[0].risk_score == 45 + bonus
    assert proof(admin, ids[0])["matches"][0]["revision_snapshot"]["reputation"] == reputation


def test_typed_url_domain_and_ip_matches_do_not_sum_or_fetch_url(case: Case, admin: Login) -> None:
    ioc(admin, "domain", "bad.example")
    ioc(admin, "url", "https://bad.example/evil?A=1#fragment")
    ioc(admin)
    _, ids = normalize_inputs(
        case, admin, [auth_event(START, http={"url": "HTTPS://BAD.EXAMPLE:443/evil?A=1#fragment"})]
    )
    detect_once(processing_database(case), case.database.settings)
    assert proof(admin, ids[0])["match_count"] == 3
    assert alerts(case)[0].risk_score == 45


def test_missing_receipt_backfill_indexes_only_and_recalc_is_explicit(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = "b" * 64
    ids = normalize_events(case, admin, [hashed_powershell(digest)])
    # Reproduce a genuine older-event state, before the TI evaluation writer.
    with monkeypatch.context() as isolated:
        isolated.setattr("app.modules.detections.processing.evaluate_event", lambda *_: [])
        isolated.setattr("app.modules.detections.processing.alert_match", lambda *_: None)
        detect_once(processing_database(case), case.database.settings)
    alert = alerts(case)[0]
    assert alert.risk_score == 45 and proof(admin, ids[0])["status"] == "pending"
    ioc(admin, "hash", digest)
    response = admin.client.post(
        "/api/v1/intelligence/backfill", json={"limit": 1}, headers=admin.authorization
    )
    assert response.status_code == 200 and response.json()["events"] == 1
    assert response.json()["alerts_created"] == 0 and len(alerts(case)) == 1
    assert proof(admin, ids[0])["status"] == "evaluated"
    with Session(case.database.runtime) as db:
        assert (
            db.scalar(select(func.count()).select_from(RiskCalculation)) == 2
        )  # alert + automatic case
    response = admin.client.post(
        f"/api/v1/alerts/{alert.id}/risk/recalculate",
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert response.status_code == 200, response.text
    current = admin.client.get(
        f"/api/v1/alerts/{alert.id}/risk", headers=admin.authorization
    ).json()
    assert current["current"]["score"] == 60 and len(current["history"]) == 2
    assert current["history"][1]["policy_version"] == "risk-policy-v3"


def test_replay_receipts_use_exact_run_and_current_catalog_first_evaluation(
    case: Case, admin: Login
) -> None:
    record = ioc(admin)
    first_scope, second_scope = (uuid4(), uuid4()), (uuid4(), uuid4())
    _, first = normalize_inputs(case, admin, [auth_event(START)], replay=first_scope)
    detect_once(processing_database(case), case.database.settings)
    patch(admin, record, reputation="clean")
    _, second = normalize_inputs(case, admin, [auth_event(START)], replay=second_scope)
    detect_once(processing_database(case), case.database.settings)
    assert proof(admin, first[0])["matches"][0]["revision_snapshot"]["reputation"] == "malicious"
    assert proof(admin, second[0])["matches"][0]["revision_snapshot"]["reputation"] == "clean"
    assert alerts(case)[0].run_id == first_scope[1] and len(alerts(case)) == 1


def test_failed_publication_rolls_back_ioc_ledger_job_and_alert(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    ioc(admin)
    _, ids = normalize_inputs(case, admin, [auth_event(START)])

    def fail(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("test-only atomic publication failure")

    with monkeypatch.context() as isolated:
        isolated.setattr("app.modules.detections.processing.score_subject", fail)
        with pytest.raises(RuntimeError, match="test-only"):
            detect_once(processing_database(case), case.database.settings)
    with Session(case.database.runtime) as db:
        assert db.scalar(select(func.count()).select_from(IntEventReceipt)) == 0
        assert db.scalar(select(func.count()).select_from(IntEventMatch)) == 0
        assert db.get(DetectionJob, ids[0]).state == "pending"
    assert not alerts(case)
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 1


def test_match_snapshot_damage_is_rejected_by_read_and_recalc(case: Case, admin: Login) -> None:
    ioc(admin)
    _, ids = normalize_inputs(case, admin, [auth_event(START)])
    detect_once(processing_database(case), case.database.settings)
    with case.database.owner.begin() as db:
        db.execute(text("ALTER TABLE int_event_matches DISABLE TRIGGER USER"))
        db.execute(
            text(
                "UPDATE int_event_matches SET revision_snapshot="
                "jsonb_set(revision_snapshot,'{source}','\"tampered\"'::jsonb)"
            )
        )
        db.execute(text("ALTER TABLE int_event_matches ENABLE TRIGGER USER"))
    response = admin.client.get(
        f"/api/v1/intelligence/events/{ids[0]}", headers=admin.authorization
    )
    assert response.status_code == 409
    alert = alerts(case)[0]
    response = admin.client.post(
        f"/api/v1/alerts/{alert.id}/risk/recalculate",
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert response.status_code == 409


def test_large_context_set_is_bounded_reports_truncation_and_keeps_maximum(
    case: Case, admin: Login
) -> None:
    ioc(admin)
    ioc(admin, "domain", "bad.example", confidence=0)
    ioc(admin, "url", "https://bad.example/", confidence=0)
    _, ids = normalize_inputs(
        case,
        admin,
        [
            auth_event(START + timedelta(seconds=index), http={"url": "https://bad.example/"})
            for index in range(34)
        ],
    )
    database = processing_database(case)
    for _ in range(3):
        detect_once(database, case.database.settings)
    with Session(case.database.runtime) as db:
        events = {
            row.event_id: NormalizedSecurityEvent.model_validate(row.document)
            for row in db.scalars(select(NormalizedEvent).where(NormalizedEvent.event_id.in_(ids)))
        }
        facts, metadata = matching.risk_contexts(db, events)
    assert len(facts) == metadata["selected_matches"] == 100
    assert metadata["available_matches"] == 102 and metadata["truncated"]
    assert len([fact for fact in facts if fact.confidence == 90]) == 34
    assert all(row.risk_score == 45 for row in alerts(case))
