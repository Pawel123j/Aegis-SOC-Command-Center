"""Independent real-database checks for incident authority and durable evidence."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core.permissions import Role
from app.infrastructure.database import ADMIN_LOCK_ID, utcnow
from app.modules.audit.models import AuditLog
from app.modules.auth.models import AuthSession
from app.modules.detections.models import DetectionJob
from app.modules.incidents.models import Incident, IncidentAlert, IncidentNote, IncidentTimeline
from app.modules.users.models import User

from .helper_ingestion import enroll, processing_database
from .helpers import Case, Login
from .test_initial_alerts import alerts, detect_once, normalize_events, powershell, user

pytestmark = pytest.mark.integration


def create_incident(principal: Login, **changes: Any) -> dict[str, Any]:
    response = principal.client.post(
        "/api/v1/incidents",
        json={"title": "Independent incident security review", **changes},
        headers={**principal.authorization, "Idempotency-Key": uuid4().hex},
    )
    assert response.status_code == 201, response.text
    return response.json()


def patch_incident(principal: Login, incident: dict[str, Any], **changes: Any) -> Any:
    return principal.client.patch(
        f"/api/v1/incidents/{incident['id']}",
        json=changes,
        headers={**principal.authorization, "If-Match": f'"{incident["version"]}"'},
    )


def stored_counts(case: Case) -> dict[str, int]:
    with Session(case.database.runtime) as session:
        return {
            model.__tablename__: int(session.scalar(select(func.count()).select_from(model)) or 0)
            for model in (Incident, IncidentAlert, IncidentNote, IncidentTimeline)
        }


def test_readonly_and_collector_cannot_change_cases(case: Case, admin: Login) -> None:
    incident = create_incident(admin)
    reader = user(case, admin, "read_only")
    source = enroll(admin)
    path = f"/api/v1/incidents/{incident['id']}"
    for resource in ("/api/v1/incidents", path, f"{path}/timeline"):
        assert reader.client.get(resource, headers=reader.authorization).status_code == 200
        assert admin.client.get(resource, headers=source.authorization).status_code == 401

    before = stored_counts(case)
    for authorization, expected in ((reader.authorization, 403), (source.authorization, 401)):
        headers = {**authorization, "If-Match": '"1"', "Idempotency-Key": uuid4().hex}
        operations = [
            ("post", "/api/v1/incidents", {"title": "Permission bypass"}),
            ("patch", path, {"title": "Permission bypass"}),
            ("post", f"{path}/notes", {"body": "Permission bypass"}),
            ("post", f"{path}/alerts", {"alert_id": str(uuid4())}),
        ]
        for method, route, body in operations:
            response = getattr(admin.client, method)(route, json=body, headers=headers)
            assert response.status_code == expected
        response = admin.client.delete(f"{path}/alerts/{uuid4()}", headers=headers)
        assert response.status_code == expected
    assert stored_counts(case) == before
    assert reader.client.get("/api/v1/audit", headers=reader.authorization).status_code == 403


def test_assignment_and_reopen_capabilities_are_enforced(case: Case, admin: Login) -> None:
    analyst = user(case, admin, "soc_analyst")
    other = user(case, admin, "soc_analyst")
    manager = user(case, admin, "soc_manager")
    reader = user(case, admin, "read_only")
    incident = create_incident(analyst)
    denied = patch_incident(analyst, incident, owner_id=other.user_id)
    assert denied.status_code == 403
    assigned = patch_incident(analyst, incident, owner_id=analyst.user_id)
    assert assigned.status_code == 200
    incident = assigned.json()
    assert incident["owner_id"] == analyst.user_id
    invalid = patch_incident(manager, incident, owner_id=reader.user_id)
    assert invalid.status_code in {409, 422}
    assigned = patch_incident(manager, incident, owner_id=other.user_id)
    assert assigned.status_code == 200 and assigned.json()["owner_id"] == other.user_id
    incident = assigned.json()
    for target in ("investigating", "resolved", "closed"):
        transitioned = patch_incident(
            analyst,
            incident,
            status=target,
            status_reason="Reviewed evidence and documented outcome",
        )
        assert transitioned.status_code == 200, transitioned.text
        incident = transitioned.json()
        if target == "resolved":
            assert (
                patch_incident(
                    analyst,
                    incident,
                    status="investigating",
                    status_reason="Analyst attempted to reopen a resolved case",
                    title="A combined edit cannot bypass reopen authority",
                ).status_code
                == 403
            )
            reopened = patch_incident(
                manager,
                incident,
                status="investigating",
                status_reason="Supervisor requested additional analysis",
            )
            assert reopened.status_code == 200
            resolved = patch_incident(
                analyst,
                reopened.json(),
                status="resolved",
                status_reason="Additional evidence reviewed",
            )
            assert resolved.status_code == 200
            incident = resolved.json()
    assert patch_incident(analyst, incident, title="Silent closed case rewrite").status_code == 409
    assert (
        patch_incident(
            analyst, incident, status="investigating", status_reason="Further analysis requested"
        ).status_code
        == 403
    )
    reopened = patch_incident(
        manager, incident, status="investigating", status_reason="New evidence needs review"
    )
    assert reopened.status_code == 200 and reopened.json()["status"] == "investigating"


@pytest.mark.parametrize("change", ["role", "disabled", "revoked", "absolute", "idle"])
def test_authority_is_revalidated_after_waiting_for_mutation_lock(
    case: Case, admin: Login, change: str
) -> None:
    analyst = user(case, admin, "soc_analyst")
    incident = create_incident(analyst)
    before = stored_counts(case)
    mutation_reached_lock = Event()
    engine = analyst.client.app.state.database.engine

    def observe_lock(
        connection: Any,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        if "pg_advisory_xact_lock" in statement:
            mutation_reached_lock.set()

    event.listen(engine, "before_cursor_execute", observe_lock)
    try:
        with case.database.owner.connect() as blocker:
            blocker.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": ADMIN_LOCK_ID})
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    patch_incident, analyst, incident, title="Unauthorized change"
                )
                try:
                    assert mutation_reached_lock.wait(timeout=3), (
                        "Mutation did not reach authority lock"
                    )
                    # Only this test's isolated database is changed. The real route
                    # has already authenticated the cached principal and now waits.
                    with Session(case.database.owner) as session:
                        user_id = UUID(analyst.user_id)
                        now = utcnow()
                        if change == "role":
                            session.execute(
                                update(User).where(User.id == user_id).values(role=Role.READ_ONLY)
                            )
                        elif change == "disabled":
                            session.execute(
                                update(User).where(User.id == user_id).values(enabled=False)
                            )
                        else:
                            changes = {
                                "revoked": {"revoked_at": now},
                                "absolute": {"absolute_expires_at": now - timedelta(seconds=1)},
                                "idle": {
                                    "last_seen_at": now
                                    - timedelta(
                                        seconds=case.database.settings.session_idle_seconds + 10
                                    )
                                },
                            }
                            session.execute(
                                update(AuthSession)
                                .where(AuthSession.user_id == user_id)
                                .values(**changes[change])
                            )
                        session.commit()
                finally:
                    blocker.rollback()
                response = future.result(timeout=10)
    finally:
        event.remove(engine, "before_cursor_execute", observe_lock)
    assert response.status_code == 403
    assert stored_counts(case) == before
    detail = admin.client.get(f"/api/v1/incidents/{incident['id']}", headers=admin.authorization)
    assert detail.status_code == 200 and detail.json()["version"] == incident["version"]
    assert detail.json()["title"] == incident["title"]


def test_concurrent_incident_edit_has_one_winner_and_one_audit(case: Case, admin: Login) -> None:
    incident = create_incident(admin)
    second = case.login("initial_admin", admin.password)
    before = stored_counts(case)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(patch_incident, admin, incident, title="First analyst decision")
        other = executor.submit(patch_incident, second, incident, title="Second analyst decision")
        responses = [first.result(timeout=10), other.result(timeout=10)]
    assert sorted(response.status_code for response in responses) == [200, 412]
    winner = next(response.json() for response in responses if response.status_code == 200)
    assert winner["version"] == incident["version"] + 1
    assert stored_counts(case)["incident_timeline"] == before["incident_timeline"] + 1
    with Session(case.database.runtime) as session:
        changes = list(
            session.scalars(
                select(AuditLog).where(
                    AuditLog.action == "incident.fields_updated",
                    AuditLog.object_id == incident["id"],
                )
            )
        )
        assert len(changes) == 1


def test_late_alert_does_not_reopen_or_change_closed_incident(case: Case, admin: Login) -> None:
    incident = create_incident(admin)
    for target in ("investigating", "resolved", "closed"):
        response = patch_incident(
            admin, incident, status=target, status_reason="Case reviewed and completed"
        )
        assert response.status_code == 200, response.text
        incident = response.json()
    before = stored_counts(case)
    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    late_alert = alerts(case)[0]
    path = f"/api/v1/incidents/{incident['id']}"
    denied = admin.client.post(
        f"{path}/alerts",
        json={"alert_id": str(late_alert.id)},
        headers={**admin.authorization, "If-Match": f'"{incident["version"]}"'},
    )
    assert denied.status_code == 409
    detail = admin.client.get(path, headers=admin.authorization)
    assert detail.status_code == 200
    assert detail.json()["status"] == "closed" and detail.json()["version"] == incident["version"]
    assert detail.json()["alert_count"] == 0 and detail.json()["related_alerts"] == []
    # The genuinely new High signal creates its own case and leaves the prior
    # analyst disposition intact. Arrival order is no causal correlation claim.
    assert stored_counts(case)["incidents"] == before["incidents"] + 1
    with Session(case.database.runtime) as session:
        assert (
            session.scalar(select(Incident).where(Incident.automatic_alert_id == late_alert.id))
            is not None
        )


def test_supported_unicode_text_fits_bounded_audit_without_losing_original(
    case: Case, admin: Login
) -> None:
    original = "ż" * 10000
    changed = "界" * 10000
    body = "界" * 5000
    incident = create_incident(admin, description=original)
    edited = patch_incident(admin, incident, description=changed)
    assert edited.status_code == 200, edited.text
    incident = edited.json()
    path = f"/api/v1/incidents/{incident['id']}"
    note = admin.client.post(
        f"{path}/notes",
        json={"body": body},
        headers={**admin.authorization, "If-Match": f'"{incident["version"]}"'},
    )
    assert note.status_code == 200, note.text
    detail = admin.client.get(path, headers=admin.authorization)
    assert detail.status_code == 200 and detail.json()["description"] == changed
    notes = admin.client.get(f"{path}/notes", headers=admin.authorization)
    assert notes.status_code == 200 and notes.json()["items"][0]["body"] == body
    with Session(case.database.runtime) as session:
        rows = list(session.scalars(select(AuditLog).where(AuditLog.object_id == incident["id"])))
        assert {row.action for row in rows} >= {
            "incident.fields_updated",
            "incident.note_added",
        }
        assert all(len(str(row.details).encode("utf-8")) <= 8192 for row in rows)


def test_failed_automatic_case_audit_rolls_back_alert_and_checkpoint_then_recovers(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    event_id = normalize_events(case, admin, [powershell()])[0]
    database = processing_database(case)
    before = stored_counts(case)
    from app.modules.incidents import service

    append_real_audit = service.append_audit

    def fail_case_creation(session: Session, **kwargs: Any) -> AuditLog:
        if kwargs.get("action") == "incident.created":
            raise RuntimeError("planned-automatic-case-audit-failure")
        return append_real_audit(session, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(service, "append_audit", fail_case_creation)
        with pytest.raises(RuntimeError, match="planned-automatic-case-audit-failure"):
            detect_once(database, case.database.settings)
    assert stored_counts(case) == before and alerts(case) == []
    with Session(case.database.runtime) as session:
        job = session.get(DetectionJob, event_id)
        assert job is not None and job.state == "pending" and job.processed_at is None
        assert session.scalar(select(AuditLog).where(AuditLog.action == "alert.created")) is None
    assert detect_once(database, case.database.settings)["alerts"] == 1
    assert len(alerts(case)) == 1 and stored_counts(case)["incidents"] == before["incidents"] + 1
    recovered = stored_counts(case)
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 0
    assert stored_counts(case) == recovered


@pytest.mark.parametrize("operation", ["create", "note", "attach", "detach"])
def test_failed_audit_insert_rolls_back_case_and_related_records(
    case: Case, admin: Login, operation: str
) -> None:
    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    record = alerts(case)[0]
    incident = create_incident(admin, alert_ids=[str(record.id)] if operation == "detach" else [])
    path = f"/api/v1/incidents/{incident['id']}"
    before = stored_counts(case)
    with case.database.owner.begin() as connection:
        connection.execute(text("REVOKE INSERT ON audit_logs FROM aegis_app"))
    try:
        headers = {
            **admin.authorization,
            "If-Match": f'"{incident["version"]}"',
            "Idempotency-Key": uuid4().hex,
        }
        if operation == "create":
            response = admin.client.post(
                "/api/v1/incidents", json={"title": "Must roll back"}, headers=headers
            )
        elif operation == "note":
            response = admin.client.post(
                f"{path}/notes", json={"body": "Must roll back"}, headers=headers
            )
        elif operation == "attach":
            response = admin.client.post(
                f"{path}/alerts", json={"alert_id": str(record.id)}, headers=headers
            )
        else:
            response = admin.client.delete(f"{path}/alerts/{record.id}", headers=headers)
        assert response.status_code == 503, response.text
    finally:
        with case.database.owner.begin() as connection:
            connection.execute(text("GRANT INSERT ON audit_logs TO aegis_app"))
    assert stored_counts(case) == before
    detail = admin.client.get(path, headers=admin.authorization)
    assert detail.status_code == 200 and detail.json()["version"] == incident["version"]


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE incidents SET risk_score=100 WHERE id=:id",
        "UPDATE incidents SET confidence=100 WHERE id=:id",
        "UPDATE incidents SET id=id WHERE id=:id",
        "DELETE FROM incidents WHERE id=:id",
        "UPDATE incident_timeline SET id=id WHERE incident_id=:id",
        "DELETE FROM incident_timeline WHERE incident_id=:id",
        "UPDATE incident_notes SET id=id WHERE incident_id=:id",
        "DELETE FROM incident_notes WHERE incident_id=:id",
        "UPDATE incident_create_receipts SET incident_id=incident_id WHERE incident_id=:id",
        "DELETE FROM incident_create_receipts WHERE incident_id=:id",
    ],
)
def test_runtime_cannot_rewrite_history_or_uncomputed_scores(
    case: Case, admin: Login, statement: str
) -> None:
    incident = create_incident(admin)
    path = f"/api/v1/incidents/{incident['id']}"
    note = admin.client.post(
        f"{path}/notes",
        json={"body": "Original analyst statement"},
        headers={**admin.authorization, "If-Match": f'"{incident["version"]}"'},
    )
    assert note.status_code in {200, 201}
    before = stored_counts(case)
    with Session(case.database.runtime) as session:
        with pytest.raises(DBAPIError) as denied:
            session.execute(text(statement), {"id": UUID(incident["id"])})
        assert getattr(denied.value.orig, "sqlstate", None) == "42501"
        session.rollback()
    assert stored_counts(case) == before
    detail = admin.client.get(path, headers=admin.authorization)
    assert detail.status_code == 200
    assert detail.json()["risk_score"] == 0 and detail.json()["confidence"] is None


def test_storage_rejects_partial_event_range_instead_of_accepting_sql_null(
    case: Case, admin: Login
) -> None:
    incident = create_incident(admin)
    with Session(case.database.runtime) as session:
        with pytest.raises(DBAPIError) as rejected:
            session.execute(
                text(
                    "UPDATE incidents SET alert_count=1, first_seen=now(), last_seen=NULL "
                    "WHERE id=:id"
                ),
                {"id": UUID(incident["id"])},
            )
        assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
        session.rollback()
    detail = admin.client.get(f"/api/v1/incidents/{incident['id']}", headers=admin.authorization)
    assert detail.status_code == 200
    assert detail.json()["alert_count"] == 0
    assert detail.json()["first_seen"] is None and detail.json()["last_seen"] is None
