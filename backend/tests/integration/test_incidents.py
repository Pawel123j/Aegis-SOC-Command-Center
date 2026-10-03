"""Case creation, cross-source live evidence, replay isolation and paged history."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.modules.alerts.models import Alert
from app.modules.audit.models import AuditLog
from app.modules.detections.processing import process_once as detect_once
from app.modules.incidents.models import Incident, IncidentAlert, IncidentCreateReceipt
from app.modules.ingestion.models import LIVE_RUN_ID, IngestionSource
from app.modules.ingestion.processing import process_event
from app.modules.normalization.processing import process_once as normalize_once

from .helper_ingestion import accept, enroll, processing_database, status
from .helpers import Case, Login
from .test_initial_alerts import alerts, normalize_events, powershell, user

pytestmark = pytest.mark.integration


def create(admin: Login, **data: Any) -> dict[str, Any]:
    response = admin.client.post(
        "/api/v1/incidents",
        json={"title": "Investigation", **data},
        headers={**admin.authorization, "Idempotency-Key": uuid4().hex},
    )
    assert response.status_code == 201, response.text
    assert response.headers["etag"] == f'"{response.json()["version"]}"'
    return response.json()


def mutate(admin: Login, incident: dict[str, Any], **data: Any) -> Any:
    return admin.client.patch(
        f"/api/v1/incidents/{incident['id']}",
        json=data,
        headers={**admin.authorization, "If-Match": f'"{incident["version"]}"'},
    )


def scoped_alert(
    case: Case,
    admin: Login,
    *,
    mode: str = "live",
    dataset: UUID | None = None,
    run: UUID | None = None,
) -> Alert:
    source = enroll(admin, source_types=["windows_process"])
    with Session(case.database.owner) as session:
        session.execute(
            update(IngestionSource)
            .where(IngestionSource.id == source.id)
            .values(
                mode=mode,
                dataset_id=dataset or uuid4(),
                run_id=run or LIVE_RUN_ID,
            )
        )
        session.commit()
    receipt = accept(
        admin.client, source, {"events": [dict(powershell(), source_event_id=uuid4().hex)]}
    )
    identifier = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)
    assert process_event(database, case.database.settings, identifier, 1) == "staged"
    normalize_once(database, case.database.settings, lambda _: None)
    assert detect_once(database, case.database.settings)["alerts"] == 1
    with Session(case.database.runtime, expire_on_commit=False) as session:
        result = session.scalar(select(Alert).where(Alert.event_id == identifier))
        assert result is not None
        return result


def test_manual_empty_creation_is_idempotent_actor_bound_and_has_no_fake_scores(
    case: Case, admin: Login
) -> None:
    key = uuid4().hex
    body = {
        "title": "Manual investigation",
        "description": "Analyst context",
        "tags": ["SOC", "Review"],
    }
    headers = {**admin.authorization, "Idempotency-Key": key}
    first = admin.client.post("/api/v1/incidents", json=body, headers=headers)
    assert first.status_code == 201
    incident = first.json()
    assert incident["risk_score"] == 0 and incident["confidence"] is None
    assert all(
        part["status"] == "not_applicable" for part in incident["risk_explanation"]["components"]
    )
    assert (
        incident["alert_count"] == 0
        and incident["first_seen"] is None
        and incident["last_seen"] is None
    )
    assert incident["mode"] == "live" and incident["dataset_id"] is None
    assert incident["run_id"] == str(LIVE_RUN_ID) and incident["dataset_ids"] == []
    assert incident["tags"] == ["review", "soc"]
    edited = mutate(admin, incident, description="Updated analyst context")
    assert edited.status_code == 200
    repeated = admin.client.post("/api/v1/incidents", json=body, headers=headers)
    assert repeated.status_code == 200 and repeated.json()["id"] == incident["id"]
    assert repeated.json()["description"] == "Updated analyst context"
    changed = admin.client.post(
        "/api/v1/incidents", json={**body, "title": "Different"}, headers=headers
    )
    assert changed.status_code == 409
    analyst = user(case, admin, "soc_analyst")
    other = analyst.client.post(
        "/api/v1/incidents", json=body, headers={**analyst.authorization, "Idempotency-Key": key}
    )
    assert other.status_code == 201 and other.json()["id"] != incident["id"]
    with Session(case.database.runtime) as session:
        assert session.scalar(select(func.count()).select_from(Incident)) == 2
        assert session.scalar(select(func.count()).select_from(IncidentCreateReceipt)) == 2


def test_new_high_alerts_create_distinct_atomic_cases_without_medium_or_historical_backfill(
    case: Case, admin: Login
) -> None:
    normalize_events(
        case,
        admin,
        [
            powershell(),
            powershell(),
            {
                "source_type": "linux_auth",
                "timestamp": "2026-10-01T12:00:00Z",
                "raw_event": (
                    "Oct  1 12:00:00 host sudo[1]: alice : TTY=pts/0 ; "
                    "PWD=/home/alice ; USER=root ; COMMAND=/bin/bash -i"
                ),
            },
        ],
    )
    database = processing_database(case)
    assert detect_once(database, case.database.settings)["alerts"] == 3
    with Session(case.database.runtime) as session:
        records = list(session.scalars(select(Incident)))
        assert len(records) == 2
        high = {alert.id for alert in alerts(case) if alert.severity == "high"}
        assert {row.automatic_alert_id for row in records} == high
        assert all(
            row.status == "new" and row.alert_count == 1 and row.owner_id is None for row in records
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(AuditLog.action == "incident.created")
            )
            == 2
        )
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 0
    with Session(case.database.runtime) as session:
        assert session.scalar(select(func.count()).select_from(Incident)) == 2


def test_live_case_spans_sources_derives_entities_and_retains_detached_evidence(
    case: Case, admin: Login
) -> None:
    original = scoped_alert(case, admin)
    payload = deepcopy(powershell())
    payload["timestamp"] = "2026-10-01T12:10:00Z"
    payload["raw_event"]["Computer"] = "second-host"
    payload["raw_event"]["EventData"]["SubjectUserName"] = "bob"
    normalize_events(case, admin, [payload])
    detect_once(processing_database(case), case.database.settings)
    other = next(alert for alert in alerts(case) if alert.id != original.id)
    incident = create(admin, alert_ids=[str(original.id)], severity="low")
    path = f"/api/v1/incidents/{incident['id']}"
    attached = admin.client.post(
        f"{path}/alerts",
        json={"alert_id": str(other.id)},
        headers={**admin.authorization, "If-Match": f'"{incident["version"]}"'},
    )
    assert attached.status_code == 200, attached.text
    current = attached.json()
    assert current["version"] == incident["version"] + 1 and current["alert_count"] == 2
    assert current["severity"] == "low"  # The analyst's assessment is not silently overwritten.
    assert set(current["dataset_ids"]) == {str(original.dataset_id), str(other.dataset_id)}
    assert set(current["related_users"]) == {r"LAB\alice", r"LAB\bob"}
    assert set(current["related_hosts"]) == {"host żółć", "second-host"}
    assert current["mitre_techniques"] == ["T1059.001"]
    assert current["first_seen"].startswith("2026-10-01T12:00:00") and current[
        "last_seen"
    ].startswith("2026-10-01T12:10:00")
    detached = admin.client.delete(
        f"{path}/alerts/{original.id}",
        headers={**admin.authorization, "If-Match": f'"{current["version"]}"'},
    )
    assert detached.status_code == 200 and detached.json()["version"] == current["version"] + 1
    assert detached.json()["alert_count"] == 1 and detached.json()["related_users"] == [r"LAB\bob"]
    evidence = admin.client.get(f"{path}/evidence", headers=admin.authorization)
    assert evidence.status_code == 200 and evidence.json()["total"] == 2
    archived = next(row for row in evidence.json()["items"] if row["alert_id"] == str(original.id))
    assert archived["active"] is False and archived["detached_at"]
    assert (
        archived["event_snapshot"] == original.event_snapshot
        and archived["event_sha256"] == original.event_sha256
    )
    reattached = admin.client.post(
        f"{path}/alerts",
        json={"alert_id": str(original.id)},
        headers={**admin.authorization, "If-Match": f'"{detached.json()["version"]}"'},
    )
    assert reattached.status_code == 200 and reattached.json()["evidence_count"] == 2
    assert reattached.json()["alert_count"] == 2


def test_replay_cases_reject_other_modes_runs_and_datasets_in_api_and_storage(
    case: Case, admin: Login
) -> None:
    dataset, run = uuid4(), uuid4()
    first = scoped_alert(case, admin, mode="replay", dataset=dataset, run=run)
    same = scoped_alert(case, admin, mode="replay", dataset=dataset, run=run)
    others = [
        scoped_alert(case, admin),
        scoped_alert(case, admin, mode="replay", dataset=dataset, run=uuid4()),
        scoped_alert(case, admin, mode="replay", dataset=uuid4(), run=run),
    ]
    incident = create(admin, alert_ids=[str(first.id), str(same.id)])
    assert (
        incident["mode"] == "replay"
        and incident["dataset_id"] == str(dataset)
        and incident["run_id"] == str(run)
    )
    for alert in others:
        response = admin.client.post(
            f"/api/v1/incidents/{incident['id']}/alerts",
            json={"alert_id": str(alert.id)},
            headers={**admin.authorization, "If-Match": f'"{incident["version"]}"'},
        )
        assert response.status_code == 409 and response.json()["code"] == "incident_scope_mismatch"
        with Session(case.database.runtime) as session:
            session.add(
                IncidentAlert(id=uuid4(), incident_id=UUID(incident["id"]), alert_id=alert.id)
            )
            with pytest.raises(DBAPIError) as rejected:
                session.commit()
            assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
            session.rollback()
    live = create(admin)
    mismatch = admin.client.post(
        f"/api/v1/incidents/{live['id']}/alerts",
        json={"alert_id": str(first.id)},
        headers={**admin.authorization, "If-Match": f'"{live["version"]}"'},
    )
    assert mismatch.status_code == 409


def test_history_and_notes_are_complete_through_scope_bound_pagination(
    case: Case, admin: Login
) -> None:
    incident = create(admin)
    path = f"/api/v1/incidents/{incident['id']}"
    bodies = [f"Analyst observation {number}" for number in range(55)]
    for body in bodies:
        response = admin.client.post(
            f"{path}/notes",
            json={"body": body},
            headers={**admin.authorization, "If-Match": f'"{incident["version"]}"'},
        )
        assert response.status_code == 200, response.text
        assert response.json()["version"] == incident["version"] + 1
        incident = response.json()
    assert len(incident["notes"]) == 50 and len(incident["timeline"]) == 50
    for resource, expected in (("notes", 55), ("timeline", 56)):
        cursor = None
        identifiers: set[str] = set()
        recovered: set[str] = set()
        while True:
            params: dict[str, str] = {"limit": "17"}
            if cursor:
                params["cursor"] = cursor
            page = admin.client.get(
                f"{path}/{resource}", params=params, headers=admin.authorization
            )
            assert page.status_code == 200 and page.json()["total"] == expected
            rows = page.json()["items"]
            assert not identifiers.intersection(row["id"] for row in rows)
            identifiers.update(row["id"] for row in rows)
            if resource == "notes":
                recovered.update(row["body"] for row in rows)
            cursor = page.json()["next_cursor"]
            if cursor is None:
                break
        assert len(identifiers) == expected
        if resource == "notes":
            assert recovered == set(bodies)
    first = admin.client.get(
        f"{path}/notes", params={"limit": "1"}, headers=admin.authorization
    ).json()
    cursor = first["next_cursor"]
    reader = user(case, admin, "read_only")
    params = {"limit": "1", "cursor": cursor}
    assert (
        reader.client.get(f"{path}/notes", params=params, headers=reader.authorization).status_code
        == 422
    )
    assert (
        admin.client.get(f"{path}/timeline", params=params, headers=admin.authorization).status_code
        == 422
    )


def test_incident_list_filters_signed_cursor_and_idempotent_concurrent_creation(
    case: Case, admin: Login
) -> None:
    key = uuid4().hex
    second = case.login("initial_admin", admin.password)

    def post(principal: Login) -> Any:
        return principal.client.post(
            "/api/v1/incidents",
            json={"title": "Once", "tags": ["review"]},
            headers={**principal.authorization, "Idempotency-Key": key},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(post, (admin, second)))
    assert sorted(result.status_code for result in results) == [200, 201]
    assert results[0].json()["id"] == results[1].json()["id"]
    for number in range(3):
        create(admin, title=f"Case {number}", tags=["review"])
    first = admin.client.get(
        "/api/v1/incidents",
        params={"limit": "2", "tag": "review", "mode": "live"},
        headers=admin.authorization,
    )
    assert first.status_code == 200 and first.json()["total"] == 4
    cursor = first.json()["next_cursor"]
    continuation = {"limit": "2", "tag": "review", "mode": "live", "cursor": cursor}
    last = admin.client.get("/api/v1/incidents", params=continuation, headers=admin.authorization)
    assert last.status_code == 200 and last.json()["next_cursor"] is None
    assert len({row["id"] for page in (first, last) for row in page.json()["items"]}) == 4
    invalid = admin.client.get(
        "/api/v1/incidents", params={**continuation, "tag": "other"}, headers=admin.authorization
    )
    assert invalid.status_code == 422


def test_input_boundaries_status_reasons_and_combined_version_are_explicit(
    case: Case, admin: Login
) -> None:
    assert (
        admin.client.post(
            "/api/v1/incidents", json={"title": "Case"}, headers=admin.authorization
        ).status_code
        == 428
    )
    for data in (
        {"title": "Case", "risk_score": 50},
        {"title": "Case", "confidence": 70},
        {"title": "Case", "mode": "replay"},
        {"title": "Case", "mode": "live", "dataset_id": str(uuid4())},
    ):
        assert (
            admin.client.post(
                "/api/v1/incidents",
                json=data,
                headers={**admin.authorization, "Idempotency-Key": uuid4().hex},
            ).status_code
            == 422
        )
    incident = create(admin)
    assert (
        mutate(
            admin, incident, status="contained", status_reason="Skipped investigation"
        ).status_code
        == 409
    )
    assert mutate(admin, incident, status="resolved").status_code == 422
    changed = mutate(
        admin,
        incident,
        title="Reviewed case",
        severity="critical",
        tags=["priority"],
        owner_id=admin.user_id,
    )
    assert changed.status_code == 200 and changed.json()["version"] == incident["version"] + 1
    assert changed.json()["owner_id"] == admin.user_id and changed.json()["severity"] == "critical"
    assert mutate(admin, changed.json(), title="Reviewed case").status_code == 409
    assert mutate(admin, incident, title="Stale edit").status_code == 412
