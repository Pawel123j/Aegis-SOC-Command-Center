"""Durable initial alerts, human authorization, evidence and pure rule testing."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.modules.alerts.models import Alert
from app.modules.audit.models import AuditLog
from app.modules.detections.models import DetectionJob, RuleDeployment
from app.modules.detections.processing import process_once as detect_once
from app.modules.ingestion.processing import process_event
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.models import NormalizedEvent
from app.modules.normalization.processing import process_once as normalize_once

from .helper_ingestion import accept, enroll, processing_database, status
from .helpers import Case, Login

pytestmark = pytest.mark.integration
RULE = "powershell-suspicious-command"


def powershell(command: str = "powershell.exe -EncodedCommand QQ==") -> dict[str, Any]:
    return {
        "source_type": "windows_process",
        "timestamp": "2026-10-01T12:00:00Z",
        "raw_event": {
            "EventID": 4688,
            "Computer": "host żółć",
            "EventData": {
                "SubjectUserName": "alice",
                "SubjectDomainName": "LAB",
                "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": command,
            },
        },
    }


def normalize_events(case: Case, admin: Login, events: list[dict[str, Any]]) -> list[UUID]:
    source = enroll(admin, source_types=sorted({event["source_type"] for event in events}))
    payload = [dict(event, source_event_id=f"alerts-{uuid4().hex}") for event in events]
    receipt = accept(admin.client, source, {"events": payload})
    ids = [UUID(row["event_id"]) for row in status(admin.client, source, receipt)["records"]]
    database = processing_database(case)
    for event_id in ids:
        assert process_event(database, case.database.settings, event_id, 1) == "staged"
    # These tests isolate PostgreSQL detection; real ClickHouse projection has its
    # own integration suite. A successful callback clears the projection backlog.
    projected: list[dict[str, Any]] = []
    normalize_once(database, case.database.settings, projected.append)
    assert {UUID(document["event_id"]) for document in projected} == set(ids)
    return ids


def alerts(case: Case) -> list[Alert]:
    with Session(case.database.runtime, expire_on_commit=False) as session:
        return list(session.scalars(select(Alert).order_by(Alert.id)))


def counts(case: Case) -> dict[str, int]:
    with Session(case.database.runtime) as session:
        return {
            model.__tablename__: int(session.scalar(select(func.count()).select_from(model)) or 0)
            for model in (Alert, DetectionJob, RuleDeployment, AuditLog)
        }


def user(case: Case, admin: Login, role: str) -> Login:
    created = case.create_user(admin, role)
    return case.login(str(created["username"]), str(created["password"]))


def test_raw_normalized_detection_alert_evidence_survives_retry_and_restart(
    case: Case, admin: Login
) -> None:
    ids = normalize_events(case, admin, [powershell()])
    database = processing_database(case)
    detect_once(database, case.database.settings)
    records = alerts(case)
    assert len(records) == 1
    record = records[0]
    assert record.event_id == ids[0] and record.rule_id == RULE and record.status == "new"
    assert record.risk_score is None and record.rule_version == "1.0.0"
    assert record.rule_snapshot["mitre"] == ["T1059.001"]
    assert hashlib.sha256(canonical_json(record.event_snapshot)).hexdigest() == record.event_sha256
    with Session(case.database.runtime) as session:
        snapshot = session.get(NormalizedEvent, ids[0])
        checkpoint = session.get(DetectionJob, ids[0])
        assert snapshot is not None and snapshot.document == record.event_snapshot
        assert checkpoint is not None and checkpoint.state == "processed"
        assert checkpoint.evaluated_rules
    before = counts(case)
    detect_once(database, case.database.settings)
    restarted = processing_database(case)
    detect_once(restarted, case.database.settings)
    assert counts(case) == before
    detail = admin.client.get(f"/api/v1/alerts/{record.id}", headers=admin.authorization)
    assert detail.status_code == 200 and detail.headers["etag"] == '"1"'
    body = detail.json()
    assert (
        body["event_snapshot"] == record.event_snapshot
        and body["rule_snapshot"] == record.rule_snapshot
    )
    assert body["reason"]["code"] == "encoded_command_argument"
    assert (
        body["reason"]["matched_fields"]["process.command_line"]
        == "powershell.exe -EncodedCommand QQ=="
    )
    assert body["risk_score"] is None


def test_all_three_builtin_rules_create_distinct_explanatory_alerts(
    case: Case, admin: Login
) -> None:
    events = [
        powershell(),
        {
            "source_type": "linux_auth",
            "timestamp": "2026-10-01T12:00:00Z",
            "raw_event": "Oct  1 12:00:00 host sudo[1]: alice : TTY=pts/0 ; "
            "PWD=/home/alice ; USER=root ; COMMAND=/bin/bash -i",
        },
        {
            "source_type": "windows_auth",
            "timestamp": "2026-10-01T12:00:00Z",
            "raw_event": {
                "EventID": 4732,
                "EventData": {
                    "SubjectUserName": "operator",
                    "MemberSid": "S-1-5-21-1-1234",
                    "TargetSid": "S-1-5-32-544",
                    "TargetUserName": "Administrators",
                },
            },
        },
    ]
    normalize_events(case, admin, events)
    detect_once(processing_database(case), case.database.settings)
    records = alerts(case)
    assert {row.rule_id for row in records} == {
        RULE,
        "linux-root-session",
        "windows-local-admin-member-added",
    }
    assert all(row.reason["summary"] and row.event_snapshot["source"]["name"] for row in records)
    assert (
        next(row for row in records if row.rule_id == "linux-root-session").rule_snapshot["mitre"]
        == []
    )


def test_concurrent_detection_sweeps_emit_once(case: Case, admin: Login) -> None:
    normalize_events(case, admin, [powershell(), powershell()])
    database = processing_database(case)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(detect_once, database, case.database.settings) for _ in range(2)]
        for future in futures:
            future.result(timeout=10)
    records = alerts(case)
    assert len(records) == 2 and len({row.detection_key for row in records}) == 2
    with Session(case.database.runtime) as session:
        assert (
            session.scalar(
                select(func.count()).select_from(AuditLog).where(AuditLog.action == "alert.created")
            )
            == 2
        )


def test_no_match_still_checkpoints_and_rule_test_has_no_effects(case: Case, admin: Login) -> None:
    ids = normalize_events(case, admin, [powershell("powershell.exe -NoProfile -Command Get-Date")])
    database = processing_database(case)
    detect_once(database, case.database.settings)
    assert alerts(case) == []
    with Session(case.database.runtime) as session:
        snapshot = session.get(NormalizedEvent, ids[0])
        job = session.get(DetectionJob, ids[0])
        assert snapshot is not None and job is not None and job.state == "processed"
        document = deepcopy(snapshot.document)
    document["process"]["command_line"] = "powershell.exe -EncodedCommand QQ=="
    before = counts(case)
    response = admin.client.post(
        "/api/v1/detections/test",
        json={"id": RULE, "events": [document]},
        headers=admin.authorization,
    )
    assert response.status_code == 200 and len(response.json()["matches"]) == 1
    assert (
        response.json()["rule_version"] == "1.0.0"
        and response.json()["evaluator_version"] == "single-event-v1"
    )
    assert counts(case) == before
    unknown = admin.client.post(
        "/api/v1/detections/test",
        json={"id": "unknown", "events": [document]},
        headers=admin.authorization,
    )
    assert unknown.status_code == 404 and counts(case) == before
    for values in [
        {"id": RULE, "events": []},
        {"id": RULE, "events": [document] * 101},
        {"id": RULE, "events": [document], "extra": 1},
    ]:
        assert admin.client.post(
            "/api/v1/detections/test", json=values, headers=admin.authorization
        ).status_code in {413, 422}
    assert counts(case) == before


def test_analyst_acknowledgement_is_versioned_audited_and_preserves_evidence(
    case: Case, admin: Login
) -> None:
    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    original = alerts(case)[0]
    analyst = user(case, admin, "soc_analyst")
    path = f"/api/v1/alerts/{original.id}"
    assert (
        analyst.client.patch(
            path, json={"status": "acknowledged"}, headers=analyst.authorization
        ).status_code
        == 428
    )
    response = analyst.client.patch(
        path, json={"status": "acknowledged"}, headers={**analyst.authorization, "If-Match": '"1"'}
    )
    assert response.status_code == 200 and response.headers["etag"] == '"2"'
    body = response.json()
    assert body["acknowledged_by"] == analyst.user_id and body["updated_by"] == analyst.user_id
    assert body["acknowledged_at"] and body["status"] == "acknowledged"
    assert (
        body["event_snapshot"] == original.event_snapshot
        and body["rule_snapshot"] == original.rule_snapshot
    )
    stale = analyst.client.patch(
        path, json={"status": "resolved"}, headers={**analyst.authorization, "If-Match": '"1"'}
    )
    assert stale.status_code == 412
    response = analyst.client.patch(
        path, json={"status": "resolved"}, headers={**analyst.authorization, "If-Match": '"2"'}
    )
    assert response.status_code == 200 and response.json()["version"] == 3
    assert response.json()["acknowledged_at"] == body["acknowledged_at"]
    with Session(case.database.runtime) as session:
        changes = list(
            session.scalars(
                select(AuditLog)
                .where(
                    AuditLog.action == "alert.status_changed",
                    AuditLog.object_id == str(original.id),
                )
                .order_by(AuditLog.occurred_at)
            )
        )
        assert len(changes) == 2 and all(row.actor_id == UUID(analyst.user_id) for row in changes)
        assert changes[0].details == {"before": "new", "after": "acknowledged"}


def test_readonly_and_source_credentials_cannot_mutate_alerts_or_test_rules(
    case: Case, admin: Login
) -> None:
    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    record = alerts(case)[0]
    readonly = user(case, admin, "read_only")
    path = f"/api/v1/alerts/{record.id}"
    assert readonly.client.get(path, headers=readonly.authorization).status_code == 200
    assert (
        readonly.client.get("/api/v1/detections", headers=readonly.authorization).status_code == 200
    )
    assert (
        readonly.client.patch(
            path,
            json={"status": "acknowledged"},
            headers={**readonly.authorization, "If-Match": '"1"'},
        ).status_code
        == 403
    )
    assert (
        readonly.client.post(
            "/api/v1/detections/test",
            json={"id": RULE, "events": [record.event_snapshot]},
            headers=readonly.authorization,
        ).status_code
        == 403
    )
    assert alerts(case)[0].status == "new" and alerts(case)[0].version == 1
    source = enroll(admin)
    assert admin.client.get("/api/v1/alerts", headers=source.authorization).status_code == 401
    assert admin.client.get("/api/v1/detections", headers=source.authorization).status_code == 401
    assert admin.client.get(path).status_code == 401


def test_manager_deployment_toggle_stops_future_alerts_preserves_existing_snapshots(
    case: Case, admin: Login
) -> None:
    normalize_events(case, admin, [powershell()])
    database = processing_database(case)
    detect_once(database, case.database.settings)
    original = alerts(case)[0]
    manager = user(case, admin, "soc_manager")
    path = f"/api/v1/detections/{RULE}"
    catalog = manager.client.get("/api/v1/detections", headers=manager.authorization)
    assert catalog.status_code == 200 and len(catalog.json()["items"]) == 3
    view = manager.client.get(path, headers=manager.authorization)
    assert view.status_code == 200 and view.headers["etag"] == '"1"'
    assert view.json()["rule_version"] == "1.0.0" and view.json()["type"] == "single_event"
    disabled = manager.client.patch(
        path, json={"enabled": False}, headers={**manager.authorization, "If-Match": '"1"'}
    )
    assert disabled.status_code == 200 and disabled.json()["version"] == 2
    normalize_events(case, admin, [powershell()])
    detect_once(database, case.database.settings)
    assert len(alerts(case)) == 1 and alerts(case)[0].rule_snapshot == original.rule_snapshot
    test = manager.client.post(
        "/api/v1/detections/test",
        json={"id": RULE, "events": [original.event_snapshot]},
        headers=manager.authorization,
    )
    assert test.status_code == 200 and len(test.json()["matches"]) == 1
    enabled = manager.client.patch(
        path, json={"enabled": True}, headers={**manager.authorization, "If-Match": '"2"'}
    )
    assert enabled.status_code == 200 and enabled.json()["version"] == 3
    detect_once(database, case.database.settings)
    assert len(alerts(case)) == 1  # Enabling does not replay already-checkpointed events.
    normalize_events(case, admin, [powershell()])
    detect_once(database, case.database.settings)
    assert len(alerts(case)) == 2
    with Session(case.database.runtime) as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(
                    AuditLog.action == "detection.deployment_changed",
                    AuditLog.actor_id == UUID(manager.user_id),
                )
            )
            == 2
        )


def test_deployment_permission_version_and_strict_input(case: Case, admin: Login) -> None:
    analyst = user(case, admin, "soc_analyst")
    path = f"/api/v1/detections/{RULE}"
    assert (
        analyst.client.patch(
            path, json={"enabled": False}, headers={**analyst.authorization, "If-Match": '"1"'}
        ).status_code
        == 403
    )
    assert (
        admin.client.patch(path, json={"enabled": False}, headers=admin.authorization).status_code
        == 428
    )
    assert (
        admin.client.patch(
            path, json={"enabled": False}, headers={**admin.authorization, "If-Match": '"0"'}
        ).status_code
        == 412
    )
    assert (
        admin.client.patch(
            path, json={"enabled": "false"}, headers={**admin.authorization, "If-Match": '"1"'}
        ).status_code
        == 422
    )
    assert (
        admin.client.patch(
            path, json={"enabled": True}, headers={**admin.authorization, "If-Match": '"1"'}
        ).status_code
        == 409
    )
    assert (
        admin.client.get("/api/v1/detections/unknown", headers=admin.authorization).status_code
        == 404
    )
    with Session(case.database.runtime) as session:
        deployment = session.get(RuleDeployment, RULE)
        assert deployment is not None and deployment.enabled and deployment.version == 1


def test_alert_list_filters_and_scope_bound_pagination(case: Case, admin: Login) -> None:
    normalize_events(case, admin, [powershell(), powershell(), powershell()])
    detect_once(processing_database(case), case.database.settings)
    records = alerts(case)
    moment = datetime.now(UTC) - timedelta(seconds=1)
    with Session(case.database.owner) as session:
        session.execute(update(Alert).values(created_at=moment))
        session.commit()
    path = "/api/v1/alerts"
    first = admin.client.get(
        path,
        params={"limit": "2", "status": "new", "severity": "high"},
        headers=admin.authorization,
    )
    assert first.status_code == 200 and first.json()["total"] == 3
    assert first.headers["cache-control"] == "no-store"
    cursor = first.json()["next_cursor"]
    assert cursor
    continuation = {"limit": "2", "status": "new", "severity": "high", "cursor": cursor}
    second = admin.client.get(path, params=continuation, headers=admin.authorization)
    assert second.status_code == 200 and second.json()["next_cursor"] is None
    seen = [row["id"] for page in (first, second) for row in page.json()["items"]]
    assert seen == [
        str(row.id) for row in sorted(records, key=lambda row: row.id.int, reverse=True)
    ]
    other = user(case, admin, "soc_analyst")
    assert (
        other.client.get(path, params=continuation, headers=other.authorization).status_code == 422
    )
    assert (
        admin.client.get(
            path, params={**continuation, "status": "resolved"}, headers=admin.authorization
        ).status_code
        == 422
    )
    assert (
        admin.client.get(
            path, params={**continuation, "cursor": cursor + "x"}, headers=admin.authorization
        ).status_code
        == 422
    )
    assert (
        admin.client.get(
            path, params={"source_id": str(records[0].source_id)}, headers=admin.authorization
        ).json()["total"]
        == 3
    )
    assert (
        admin.client.get(
            path, params={"source_id": str(uuid4())}, headers=admin.authorization
        ).json()["total"]
        == 0
    )
    for values in [{"limit": "501"}, {"status": "unknown"}, {"extra": "x"}]:
        assert admin.client.get(path, params=values, headers=admin.authorization).status_code == 422


def test_alert_snapshot_updates_and_deletes_are_denied_to_runtime(case: Case, admin: Login) -> None:
    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    record = alerts(case)[0]
    for statement in [
        "UPDATE alerts SET event_snapshot='{}'::jsonb WHERE id=:id",
        "UPDATE alerts SET rule_snapshot='{}'::jsonb WHERE id=:id",
        "UPDATE alerts SET severity='low' WHERE id=:id",
        "DELETE FROM alerts WHERE id=:id",
    ]:
        with Session(case.database.runtime) as session:
            with pytest.raises(DBAPIError):
                session.execute(text(statement), {"id": record.id})
            session.rollback()
    assert alerts(case)[0].event_snapshot == record.event_snapshot


def test_failed_status_audit_rolls_back_analyst_decision(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    record = alerts(case)[0]

    def fail_audit(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("planned-audit-failure")

    monkeypatch.setattr("app.api.alerts.append_audit", fail_audit)
    response = admin.client.patch(
        f"/api/v1/alerts/{record.id}",
        json={"status": "acknowledged"},
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert response.status_code == 500
    preserved = alerts(case)[0]
    assert preserved.status == "new" and preserved.version == 1
    assert preserved.acknowledged_at is None and preserved.acknowledged_by is None


def test_failed_deployment_audit_rolls_back_toggle(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_audit(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("planned-audit-failure")

    monkeypatch.setattr("app.api.detections.append_audit", fail_audit)
    response = admin.client.patch(
        f"/api/v1/detections/{RULE}",
        json={"enabled": False},
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert response.status_code == 500
    with Session(case.database.runtime) as session:
        row = session.get(RuleDeployment, RULE)
        assert row is not None and row.enabled and row.version == 1


def test_operator_detection_status_and_batch_counts_use_real_checkpoints(
    case: Case, admin: Login
) -> None:
    normalize_events(case, admin, [powershell(), powershell("powershell.exe -Command Get-Date")])
    database = processing_database(case)
    assert detect_once(database, case.database.settings)["processed"] == 2
    response = admin.client.get("/api/v1/system/detections", headers=admin.authorization)
    assert response.status_code == 200
    assert response.json() == {"states": {"processed": 2}, "oldest_pending_seconds": 0}
    manager = user(case, admin, "soc_manager")
    assert (
        manager.client.get("/api/v1/system/detections", headers=manager.authorization).status_code
        == 200
    )
    reader = user(case, admin, "read_only")
    assert (
        reader.client.get("/api/v1/system/detections", headers=reader.authorization).status_code
        == 403
    )
    from app.modules.ingestion.models import IngestionBatch

    with Session(case.database.runtime) as session:
        batch = session.scalar(select(IngestionBatch))
        assert batch is not None
        batch_id = batch.id
    receipt = admin.client.get(f"/api/v1/events/batches/{batch_id}", headers=admin.authorization)
    assert receipt.status_code == 200 and receipt.json()["counts"]["processed"] == 2
    assert all(record["detection_state"] == "processed" for record in receipt.json()["records"])
