"""Real PostgreSQL temporal finalization, closed replay and immutable case proofs."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.infrastructure.database import utcnow
from app.modules.alerts.models import Alert
from app.modules.audit.models import AuditLog
from app.modules.correlation.models import CorrelationJob, CorrelationScope
from app.modules.correlation.processing import process_once
from app.modules.detections.models import RuleDeployment
from app.modules.incidents.models import Incident
from app.modules.ingestion.models import IngestionSource
from app.modules.ingestion.processing import process_event
from app.modules.ingestion.schemas import RawEnvelope, canonical_json
from app.modules.ingestion.service import accept_batch
from app.modules.normalization.models import NormalizedEvent
from app.modules.normalization.processing import process_once as normalize_once

from .helper_correlation import RULE, auth_event, auth_sequence, normalize_inputs, seal
from .helper_ingestion import accept, processing_database, status
from .helpers import Case, Login
from .test_initial_alerts import alerts

pytestmark = pytest.mark.integration
HISTORIC = datetime(2020, 1, 1, tzinfo=UTC)


def correlation_alerts(case: Case, rule_id: str = RULE) -> list[Alert]:
    return [alert for alert in alerts(case) if alert.rule_id == rule_id]


def test_ingestion_closed_replay_alert_all_proofs_and_case_survive_restart(
    case: Case, admin: Login
) -> None:
    scope = (uuid4(), uuid4())
    _, ids = normalize_inputs(case, admin, auth_sequence(HISTORIC), replay=scope)
    database = processing_database(case)
    assert process_once(database, case.database.settings)["alerts"] == 0
    manifest = seal(admin, scope, 6)
    with Session(case.database.runtime) as db:
        saved = db.get(CorrelationScope, manifest["namespace"])
        assert (
            saved
            and saved.manifest_sha256 == hashlib.sha256(canonical_json(saved.manifest)).hexdigest()
        )
    assert process_once(database, case.database.settings)["alerts"] == 2
    high = correlation_alerts(case)[0]
    assert high.event_count == 6 and high.risk_score == 55 and high.severity == "high"
    assert {item["event_id"] for item in high.event_snapshots} == {str(value) for value in ids}
    for proof in high.event_snapshots:
        assert (
            proof["event_sha256"]
            == hashlib.sha256(canonical_json(proof["event_snapshot"])).hexdigest()
        )
    detail = admin.client.get(f"/api/v1/alerts/{high.id}", headers=admin.authorization)
    assert detail.status_code == 200 and len(detail.json()["event_snapshots"]) == 6
    with Session(case.database.runtime) as db:
        incident = db.scalar(select(Incident).where(Incident.automatic_alert_id == high.id))
        assert incident is not None and incident.first_seen == HISTORIC
        assert incident.last_seen == HISTORIC + timedelta(seconds=5)
        assert incident.risk_score == 55 and incident.confidence is None

        incident_id = incident.id
        initial_audits = db.scalar(select(func.count()).select_from(AuditLog))
    proof_response = admin.client.get(
        f"/api/v1/incidents/{incident_id}/evidence", headers=admin.authorization
    )
    assert (
        proof_response.status_code == 200
        and len(proof_response.json()["items"][0]["event_snapshots"]) == 6
    )
    with Session(case.database.owner) as db:
        db.execute(
            update(CorrelationJob).where(CorrelationJob.event_id.in_(ids)).values(state="pending")
        )
        db.commit()
    restarted = processing_database(case)
    assert process_once(restarted, case.database.settings)["alerts"] == 0
    assert len(correlation_alerts(case)) == 1
    with Session(case.database.runtime) as db:
        assert db.scalar(select(func.count()).select_from(AuditLog)) == initial_audits


def test_live_waits_for_finalization_and_late_arrival_cannot_change_proof(
    case: Case, admin: Login
) -> None:
    start = utcnow() - timedelta(seconds=10)
    source, _ = normalize_inputs(case, admin, auth_sequence(start))
    database = processing_database(case)
    assert process_once(database, case.database.settings)["alerts"] == 0
    final_time = utcnow() + timedelta(seconds=125)
    assert process_once(database, case.database.settings, now=final_time)["alerts"] == 2
    high = correlation_alerts(case)[0]
    original = high.event_snapshots
    _, late_ids = normalize_inputs(
        case, admin, [auth_event(start + timedelta(seconds=4))], source=source
    )
    result = process_once(database, case.database.settings, now=final_time)
    assert result["late"] == 1 and result["alerts"] == 0
    assert correlation_alerts(case)[0].event_snapshots == original
    with Session(case.database.runtime) as db:
        job = db.get(CorrelationJob, late_ids[0])
        assert job and job.error_code == "behind_final_watermark"


@pytest.mark.parametrize(
    "offset,state", [(-121, "late"), (-119, "pending"), (29, "pending"), (31, "clock_skew")]
)
def test_live_receipt_eligibility_limits_are_durable(
    case: Case, admin: Login, offset: int, state: str
) -> None:
    _, ids = normalize_inputs(case, admin, [auth_event(utcnow() + timedelta(seconds=offset))])
    process_once(processing_database(case), case.database.settings)
    with Session(case.database.runtime) as db:
        job = db.get(CorrelationJob, ids[0])
        assert job and job.state == state
        if state != "pending":
            assert job.error_code and job.processed_at


def test_unknown_raw_backlog_blocks_frontier_then_normalization_recovers(
    case: Case, admin: Login
) -> None:
    source, _ = normalize_inputs(case, admin, auth_sequence(utcnow() - timedelta(seconds=10)))
    receipt = accept(
        admin.client,
        source,
        {"events": [{"source_type": "generic_json", "raw_event": {"message": "pending"}}]},
    )
    backlog_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)
    observed = utcnow() + timedelta(seconds=125)
    assert process_once(database, case.database.settings, now=observed)["alerts"] == 0
    with Session(case.database.runtime) as db:
        scope = db.get(CorrelationScope, "live")
        assert scope is not None and scope.watermark is None
    assert process_event(database, case.database.settings, backlog_id, 1) == "staged"
    normalize_once(database, case.database.settings, lambda _: None)
    assert process_once(database, case.database.settings, now=observed)["alerts"] == 2


def test_discovery_limit_blocks_advance_until_complete_and_processing_is_bounded(
    case: Case, admin: Login
) -> None:
    normalize_inputs(case, admin, auth_sequence(utcnow() - timedelta(seconds=10)))
    database = processing_database(case)
    settings = case.database.settings.model_copy(update={"correlation_batch_size": 1})
    observed = utcnow() + timedelta(seconds=125)
    for _ in range(5):
        result = process_once(database, settings, now=observed)
        assert result["admitted"] == 1 and result["processed"] == 0
    assert process_once(database, settings, now=observed)["processed"] == 1
    for _ in range(5):
        assert process_once(database, settings, now=observed)["processed"] == 1
    assert len(correlation_alerts(case)) == 1


def test_live_cross_source_proof_and_case_retain_every_dataset(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = auth_sequence(utcnow() - timedelta(seconds=10))
    first, _ = normalize_inputs(case, admin, records[:5])
    second, _ = normalize_inputs(case, admin, records[5:])
    assert first.id != second.id
    observed = utcnow() + timedelta(seconds=125)
    process_once(processing_database(case), case.database.settings, now=observed)
    # The worker and list snapshot must observe the same simulated wall clock.
    # Production pagination intentionally hides records created after its anchor.
    monkeypatch.setattr("app.api.alerts.utcnow", lambda: observed + timedelta(seconds=1))
    alert = correlation_alerts(case)[0]
    datasets = {item["event_snapshot"]["dataset_id"] for item in alert.event_snapshots}
    assert len(datasets) == 2
    with Session(case.database.runtime) as db:
        incident = db.scalar(select(Incident).where(Incident.automatic_alert_id == alert.id))
        assert incident and set(incident.dataset_ids) == datasets
    for source in (first, second):
        result = admin.client.get(
            "/api/v1/alerts", params={"source_id": source.id}, headers=admin.authorization
        )
        assert result.status_code == 200 and str(alert.id) in {
            row["id"] for row in result.json()["items"]
        }


def test_replay_scopes_do_not_join_and_a_new_run_has_distinct_keys(
    case: Case, admin: Login
) -> None:
    dataset, run_a, run_b = uuid4(), uuid4(), uuid4()
    records = auth_sequence(HISTORIC)
    normalize_inputs(case, admin, records[:5], replay=(dataset, run_a))
    normalize_inputs(case, admin, records[5:], replay=(dataset, run_b))
    seal(admin, (dataset, run_a), 5)
    seal(admin, (dataset, run_b), 1)
    database = processing_database(case)
    process_once(database, case.database.settings)
    assert not correlation_alerts(case)
    for _ in range(2):
        scope = (dataset, uuid4())
        normalize_inputs(case, admin, records, replay=scope)
        seal(admin, scope, 6)
        process_once(database, case.database.settings)
    matches = correlation_alerts(case)
    assert len(matches) == 2 and len({row.detection_key for row in matches}) == 2


def test_replay_seal_is_idempotent_under_concurrency_and_later_arrivals_are_excluded(
    case: Case, admin: Login
) -> None:
    scope = (uuid4(), uuid4())
    source, _ = normalize_inputs(case, admin, auth_sequence(HISTORIC), replay=scope)
    with ThreadPoolExecutor(max_workers=2) as pool:
        replies = list(pool.map(lambda _: seal(admin, scope, 6), range(2)))
    assert replies[0] == replies[1]
    with Session(case.database.runtime) as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(AuditLog.action == "correlation.replay_finalized")
            )
            == 1
        )
    _, ids = normalize_inputs(
        case, admin, [auth_event(HISTORIC + timedelta(seconds=4))], source=source
    )
    result = process_once(processing_database(case), case.database.settings)
    assert result["late"] == 1
    with Session(case.database.runtime) as db:
        late = db.get(CorrelationJob, ids[0])
        assert late and late.error_code == "outside_sealed_manifest"
    assert len(correlation_alerts(case)) == 1


def test_seal_rejects_wrong_count_missing_normalization_and_zero_run(
    case: Case, admin: Login
) -> None:
    scope = (uuid4(), uuid4())
    source, _ = normalize_inputs(case, admin, auth_sequence(HISTORIC), replay=scope)
    body = {"dataset_id": str(scope[0]), "run_id": str(scope[1]), "expected_event_count": 5}
    response = admin.client.post(
        "/api/v1/correlations/replay/finalize", json=body, headers=admin.authorization
    )
    assert response.status_code == 409 and response.json()["code"] == "replay_count_mismatch"
    accept(admin.client, source, {"events": [auth_event(HISTORIC)]})
    response = admin.client.post(
        "/api/v1/correlations/replay/finalize",
        json={**body, "expected_event_count": 7},
        headers=admin.authorization,
    )
    assert response.status_code == 409 and response.json()["code"] == "replay_not_normalized"
    response = admin.client.post(
        "/api/v1/correlations/replay/finalize",
        json={**body, "run_id": str(UUID(int=0))},
        headers=admin.authorization,
    )
    assert response.status_code == 422


def test_disabled_live_rule_uses_current_version_and_does_not_backfill(
    case: Case, admin: Login
) -> None:
    normalize_inputs(case, admin, auth_sequence(utcnow() - timedelta(seconds=10)))
    database = processing_database(case)
    process_once(database, case.database.settings)
    response = admin.client.patch(
        f"/api/v1/correlations/{RULE}",
        json={"enabled": False},
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert response.status_code == 200
    process_once(database, case.database.settings, now=utcnow() + timedelta(seconds=125))
    assert not correlation_alerts(case)
    response = admin.client.patch(
        f"/api/v1/correlations/{RULE}",
        json={"enabled": True},
        headers={**admin.authorization, "If-Match": '"2"'},
    )
    assert response.status_code == 200
    assert (
        process_once(database, case.database.settings, now=utcnow() + timedelta(seconds=125))[
            "alerts"
        ]
        == 0
    )
    with Session(case.database.runtime) as db:
        checkpoints = list(db.scalars(select(CorrelationJob)))
        assert all(
            next(item for item in row.evaluated_rules if item["id"] == RULE)["deployment_version"]
            == 2
            for row in checkpoints
        )


def test_pure_closed_test_is_permission_checked_and_does_not_persist(
    case: Case, admin: Login
) -> None:
    _, ids = normalize_inputs(case, admin, auth_sequence(HISTORIC))
    with Session(case.database.runtime) as db:
        documents = list(
            db.scalars(select(NormalizedEvent.document).where(NormalizedEvent.event_id.in_(ids)))
        )
        before = db.scalar(select(func.count()).select_from(AuditLog))
    response = admin.client.post(
        "/api/v1/correlations/test",
        json={"id": RULE, "events": list(reversed(documents))},
        headers=admin.authorization,
    )
    assert response.status_code == 200 and response.json()["complete"] is True
    assert len(response.json()["matches"]) == 1
    with Session(case.database.runtime) as db:
        assert db.scalar(select(func.count()).select_from(AuditLog)) == before
        assert db.scalar(select(func.count()).select_from(CorrelationJob)) == 0
        assert db.scalar(select(func.count()).select_from(Alert)) == 0


def test_multiple_workers_make_one_final_case_and_no_duplicate_audit(
    case: Case, admin: Login
) -> None:
    scope = (uuid4(), uuid4())
    normalize_inputs(case, admin, auth_sequence(HISTORIC), replay=scope)
    seal(admin, scope, 6)
    databases = [processing_database(case), processing_database(case)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda db: process_once(db, case.database.settings), databases))
    assert sum(result["alerts"] for result in results) == 2
    assert len(correlation_alerts(case)) == 1
    with Session(case.database.runtime) as db:
        assert db.scalar(select(func.count()).select_from(Incident)) == 1


def test_candidate_overflow_is_incomplete_and_never_creates_partial_proof(
    case: Case, admin: Login
) -> None:
    scope = (uuid4(), uuid4())
    records = [auth_event(HISTORIC + timedelta(microseconds=index)) for index in range(501)] + [
        auth_event(HISTORIC + timedelta(seconds=1), "success")
    ]
    _, ids = normalize_inputs(case, admin, records, replay=scope)
    # Disable the unrelated threshold before sealing the immutable deployment
    # set, so this test isolates the success anchor's candidate overflow.
    with Session(case.database.owner) as db:
        db.execute(
            update(RuleDeployment)
            .where(RuleDeployment.id == "repeated_authentication_failures")
            .values(enabled=False)
        )
        db.commit()
    seal(admin, scope, len(records))
    database = processing_database(case)
    settings = case.database.settings.model_copy(update={"correlation_batch_size": 200})
    for _ in range(5):
        process_once(database, settings)
    assert not correlation_alerts(case)
    with Session(case.database.runtime) as db:
        success = db.get(CorrelationJob, ids[-1])
        assert success and success.state == "incomplete" and success.error_code == "candidate_limit"
    status_response = admin.client.get("/api/v1/correlations/status", headers=admin.authorization)
    assert (
        status_response.status_code == 200 and status_response.json()["counts"]["incomplete"] >= 1
    )


def test_actual_windows_full_chain_creates_critical_nine_event_proof(
    case: Case, admin: Login
) -> None:
    host_id, principal_sid = "registered-host", "S-1-5-21-1-1001"
    inputs: list[dict[str, Any]] = []
    for index in range(6):
        inputs.append(
            {
                "source_type": "windows_auth",
                "timestamp": (HISTORIC + timedelta(seconds=index)).isoformat(),
                "raw_event": {
                    "EventID": 4624 if index == 5 else 4625,
                    "Computer": "server",
                    "host_id": host_id,
                    "EventData": {
                        "SubjectUserSid": "S-1-5-18",
                        "SubjectUserName": "SYSTEM",
                        "SubjectDomainName": "NT AUTHORITY",
                        "TargetUserSid": principal_sid if index == 5 else "S-1-0-0",
                        "TargetUserName": "Alice",
                        "TargetDomainName": "LAB",
                        "IpAddress": "192.0.2.1",
                        "TargetLogonId": "0x11",
                    },
                },
            }
        )
    inputs.extend(
        [
            {
                "source_type": "windows_process",
                "timestamp": (HISTORIC + timedelta(seconds=6)).isoformat(),
                "raw_event": {
                    "EventID": 1,
                    "ProviderName": "Microsoft-Windows-Sysmon",
                    "Computer": "server",
                    "host_id": host_id,
                    "EventData": {
                        "User": "LAB\\Alice",
                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "ProcessGuid": "process-1",
                        "ProcessId": 100,
                    },
                },
            },
            {
                "source_type": "windows_auth",
                "timestamp": (HISTORIC + timedelta(seconds=7)).isoformat(),
                "raw_event": {
                    "EventID": 4732,
                    "Computer": "server",
                    "host_id": host_id,
                    "EventData": {
                        "SubjectUserSid": principal_sid,
                        "SubjectUserName": "Alice",
                        "SubjectDomainName": "LAB",
                        "TargetSid": "S-1-5-32-544",
                        "TargetUserName": "Administrators",
                        "MemberSid": "S-1-5-21-1-1002",
                    },
                },
            },
            auth_event(
                HISTORIC + timedelta(seconds=8),
                host={"id": host_id, "name": "server", "os": "windows"},
                user={"id": principal_sid, "name": "ALICE", "realm": "LAB"},
                event={"category": "network", "action": "outbound_connection"},
                process={"entity_id": "process-1"},
                destination={"ip": "198.51.100.4"},
            ),
        ]
    )
    scope = (uuid4(), uuid4())
    _, ids = normalize_inputs(case, admin, inputs, replay=scope)
    seal(admin, scope, 9)
    result = process_once(processing_database(case), case.database.settings)
    assert result["alerts"] == 5
    critical = correlation_alerts(case, "possible_multi_stage_compromise")
    assert (
        len(critical) == 1 and critical[0].severity == "critical" and critical[0].event_count == 9
    )
    assert {item["event_id"] for item in critical[0].event_snapshots} == {
        str(value) for value in ids
    }
    with Session(case.database.runtime) as db:
        incident = db.scalar(select(Incident).where(Incident.automatic_alert_id == critical[0].id))
        assert (
            incident
            and incident.first_seen == HISTORIC
            and incident.last_seen == HISTORIC + timedelta(seconds=8)
        )
        assert "198.51.100.4" in incident.related_ip_addresses
        assert incident.risk_score == 73 and incident.confidence is None


def test_open_ingress_transaction_is_fenced_before_live_watermark(case: Case, admin: Login) -> None:
    source, _ = normalize_inputs(case, admin, auth_sequence(utcnow() - timedelta(seconds=10)))
    admitted, release = Event(), Event()

    def ingress() -> None:
        with Session(case.database.runtime) as db:
            row = db.get(IngestionSource, UUID(source.id))
            assert row is not None
            accept_batch(
                db,
                row,
                [RawEnvelope(source_type="generic_json", raw_event={"message": "open-admission"})],
                uuid4().hex,
                uuid4().hex,
                case.database.settings,
            )
            admitted.set()
            assert release.wait(timeout=5)
            db.commit()

    database = processing_database(case)
    with ThreadPoolExecutor(max_workers=2) as pool:
        input_tx = pool.submit(ingress)
        try:
            assert admitted.wait(timeout=5)
            worker = pool.submit(
                process_once,
                database,
                case.database.settings,
                now=utcnow() + timedelta(seconds=125),
            )
        finally:
            release.set()
        input_tx.result(timeout=10)
        result = worker.result(timeout=10)
    assert result["alerts"] == 0
    with Session(case.database.runtime) as db:
        scope = db.get(CorrelationScope, "live")
        assert scope is not None and scope.watermark is None
