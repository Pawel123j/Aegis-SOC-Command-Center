"""Independent adversarial tests of observed case facts, scopes and current-view cursors."""

import base64
import hashlib
import json
import random
import string
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from app.core import permissions
from app.core.permissions import Permission, Role
from app.infrastructure.database import utcnow
from app.modules.alerts.models import Alert
from app.modules.audit.models import AuditLog
from app.modules.auth.models import AuthSession
from app.modules.detections.models import DetectionJob
from app.modules.entities.models import (
    AlertEventReference,
    EntityAlertReceipt,
    EntityIdentity,
    EntityIndexReceipt,
    EntityObservation,
)
from app.modules.incidents.models import Incident, IncidentAlert, IncidentNote, IncidentTimeline
from app.modules.ingestion.models import RawEvent
from app.modules.ingestion.schemas import canonical_json
from app.modules.intelligence.models import IntEventMatch, IntEventReceipt
from app.modules.normalization.models import NormalizedEvent
from app.modules.risk.models import RiskCalculation
from app.modules.users.models import User

from .helper_correlation import auth_event, normalize_inputs
from .helper_ingestion import enroll, processing_database
from .helper_intelligence import create as create_ioc
from .helpers import Case, Login
from .test_incidents import create as create_case
from .test_initial_alerts import alerts, detect_once, powershell, user
from .test_intelligence_pipeline import hashed_powershell

pytestmark = pytest.mark.integration
START = datetime(2026, 10, 1, 12, tzinfo=UTC)


def path(incident: dict[str, Any]) -> str:
    return f"/api/v1/incidents/{incident['id']}/attack-timeline"


def response(principal: Login, incident: dict[str, Any], **params: Any) -> Any:
    return principal.client.get(path(incident), params=params, headers=principal.authorization)


def read(principal: Login, incident: dict[str, Any], **params: Any) -> dict[str, Any]:
    result = response(principal, incident, **params)
    assert result.status_code == 200, result.text
    assert result.headers["cache-control"] == "no-store"
    data = dict(result.json())
    assert data["projection_version"] == "attack-timeline-v1"
    assert data["incident_id"] == incident["id"]
    for item in data["items"]:
        assert (
            hashlib.sha256(canonical_json(item["event_snapshot"])).hexdigest()
            == item["event_sha256"]
        )
    return data


def stored_counts(case: Case) -> dict[str, int]:
    with Session(case.database.runtime) as db:
        return {
            model.__tablename__: int(db.scalar(select(func.count()).select_from(model)) or 0)
            for model in (
                RawEvent,
                NormalizedEvent,
                DetectionJob,
                Alert,
                Incident,
                IncidentAlert,
                IncidentNote,
                IncidentTimeline,
                EntityIdentity,
                EntityIndexReceipt,
                EntityObservation,
                EntityAlertReceipt,
                AlertEventReference,
                RiskCalculation,
                IntEventReceipt,
                IntEventMatch,
                AuditLog,
            )
        }


def denied_without_domain_writes(case: Case, before: dict[str, int]) -> None:
    after = stored_counts(case)
    assert {key: value for key, value in after.items() if key != "audit_logs"} == {
        key: value for key, value in before.items() if key != "audit_logs"
    }
    assert after["audit_logs"] == before["audit_logs"] + 1
    with Session(case.database.runtime) as db:
        rejection = db.scalar(
            select(AuditLog).order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc()).limit(1)
        )
        assert rejection is not None and rejection.outcome == "denied"
        assert rejection.action in {"security.rejected", "authorization.denied"}


def seed_events(
    case: Case,
    admin: Login,
    count: int = 2,
    *,
    timestamps: list[str] | None = None,
    replay: tuple[UUID, UUID] | None = None,
    legacy: bool = False,
    monkeypatch: pytest.MonkeyPatch | None = None,
) -> list[Alert]:
    inputs = [
        {
            **powershell(),
            "timestamp": timestamps[i]
            if timestamps
            else (START + timedelta(seconds=i)).isoformat(),
        }
        for i in range(count)
    ]
    _, identifiers = normalize_inputs(case, admin, inputs, replay=replay)
    if legacy:
        assert monkeypatch is not None
        with monkeypatch.context() as isolated:
            isolated.setattr("app.modules.detections.processing.index_alert", lambda *_: None)
            detect_once(processing_database(case), case.database.settings)
    else:
        detect_once(processing_database(case), case.database.settings)
    records = [item for item in alerts(case) if item.event_id in identifiers]
    assert len(records) == count
    return records


def investigate(admin: Login, records: list[Alert]) -> dict[str, Any]:
    return dict(
        create_case(
            admin, title="Independent timeline review", alert_ids=[str(item.id) for item in records]
        )
    )


def attach(admin: Login, incident: dict[str, Any], alert: Alert) -> dict[str, Any]:
    result = admin.client.post(
        f"/api/v1/incidents/{incident['id']}/alerts",
        json={"alert_id": str(alert.id)},
        headers={**admin.authorization, "If-Match": f'"{incident["version"]}"'},
    )
    assert result.status_code == 200, result.text
    return dict(result.json())


def detach(admin: Login, incident: dict[str, Any], alert: Alert) -> dict[str, Any]:
    result = admin.client.delete(
        f"/api/v1/incidents/{incident['id']}/alerts/{alert.id}",
        headers={**admin.authorization, "If-Match": f'"{incident["version"]}"'},
    )
    assert result.status_code == 200, result.text
    return dict(result.json())


def assert_changed(admin: Login, incident: dict[str, Any], cursor: str) -> None:
    result = response(admin, incident, limit=1, cursor=cursor)
    assert result.status_code == 409 and result.json()["code"] == "attack_timeline_changed", (
        result.text
    )
    assert "items" not in result.json()


@pytest.mark.parametrize(
    "missing", [Permission.INCIDENTS_READ, Permission.ALERTS_READ, Permission.EVENTS_READ]
)
def test_timeline_requires_each_of_all_three_current_read_permissions(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch, missing: Permission
) -> None:
    incident = investigate(admin, seed_events(case, admin))
    reader = user(case, admin, "read_only")
    restricted = dict(permissions.ROLE_PERMISSIONS)
    restricted[Role.READ_ONLY] -= {missing}
    monkeypatch.setattr(permissions, "ROLE_PERMISSIONS", restricted)
    before = stored_counts(case)
    result = response(reader, incident)
    assert result.status_code == 403 and result.json()["code"] == "forbidden"
    assert "items" not in result.json() and "view_fingerprint" not in result.json()
    denied_without_domain_writes(case, before)


@pytest.mark.parametrize("credential", ["anonymous", "source"])
def test_timeline_never_uses_ingestion_token_or_anonymous_access(
    case: Case, admin: Login, credential: str
) -> None:
    incident = investigate(admin, seed_events(case, admin))
    headers = {} if credential == "anonymous" else enroll(admin).authorization
    client = case.client()
    before = stored_counts(case)
    result = client.get(path(incident), headers=headers)
    assert result.status_code == 401 and result.json()["code"] == "unauthorized"
    denied_without_domain_writes(case, before)


@pytest.mark.parametrize("state", ["disabled", "revoked", "absolute", "idle"])
def test_cursor_cannot_replace_fresh_enabled_user_and_unexpired_session(
    case: Case, admin: Login, state: str
) -> None:
    incident = investigate(admin, seed_events(case, admin))
    reader = user(case, admin, "read_only")
    first = read(reader, incident, limit=1)
    assert first["next_cursor"]
    with Session(case.database.owner) as db:
        identifier = UUID(reader.user_id)
        now = utcnow()
        if state == "disabled":
            db.execute(update(User).where(User.id == identifier).values(enabled=False))
        else:
            changes = {
                "revoked": {"revoked_at": now},
                "absolute": {"absolute_expires_at": now - timedelta(seconds=1)},
                "idle": {
                    "last_seen_at": now
                    - timedelta(seconds=case.database.settings.session_idle_seconds + 10)
                },
            }[state]
            db.execute(
                update(AuthSession).where(AuthSession.user_id == identifier).values(**changes)
            )
        db.commit()
    before = stored_counts(case)
    result = response(reader, incident, limit=1, cursor=first["next_cursor"])
    assert result.status_code == 401 and "items" not in result.json()
    denied_without_domain_writes(case, before)


@pytest.mark.parametrize("attack", ["payload", "signature", "principal", "case", "limit", "expiry"])
def test_signed_cursor_is_bound_to_actor_resource_limit_and_original_expiry(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch, attack: str
) -> None:
    records = seed_events(case, admin)
    incident = investigate(admin, records)
    first = read(admin, incident, limit=1)
    token = first["next_cursor"]
    assert token
    principal, target, limit = admin, incident, 1
    if attack in {"payload", "signature"}:
        pieces = token.split(".")
        index = 0 if attack == "payload" else 1
        pieces[index] = ("A" if pieces[index][0] != "A" else "B") + pieces[index][1:]
        token = ".".join(pieces)
    elif attack == "principal":
        principal = user(case, admin, "read_only")
    elif attack == "case":
        target = investigate(admin, records)
    elif attack == "limit":
        limit = 2
    else:
        encoded = token.split(".")[0]
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        monkeypatch.setattr(
            "app.modules.attack_timeline.cursors.time.time", lambda: payload["expires"]
        )
    before = stored_counts(case)
    result = response(principal, target, limit=limit, cursor=token)
    assert result.status_code == 422 and result.json()["code"] == "invalid_cursor", result.text
    assert "items" not in result.json() and stored_counts(case) == before


def test_future_utc_microsecond_and_equal_time_rows_page_without_skips_or_duplicates(
    case: Case, admin: Login
) -> None:
    times = [
        "2099-01-01T10:00:00.123456+02:00",
        "2099-01-01T08:00:00.123456Z",
        "2099-01-01T08:00:00.123457Z",
    ]
    records = seed_events(case, admin, 3, timestamps=times)
    incident = investigate(admin, records)
    before = stored_counts(case)
    pages = [read(admin, incident, limit=1)]
    while pages[-1]["next_cursor"]:
        pages.append(read(admin, incident, limit=1, cursor=pages[-1]["next_cursor"]))
    items = [item for page in pages for item in page["items"]]
    positions = [
        (
            datetime.fromisoformat(item["event_snapshot"]["timestamp"].replace("Z", "+00:00")),
            UUID(item["event_id"]),
        )
        for item in items
    ]
    assert positions == sorted(positions) and len(set(positions)) == len(positions) == 3
    assert {identifier for _, identifier in positions} == {item.event_id for item in records}
    assert [time.microsecond for time, _ in positions] == [123456, 123456, 123457]
    assert all(time.utcoffset() == timedelta(0) for time, _ in positions)
    assert all(page["total"] == 3 for page in pages)
    assert len({page["view_fingerprint"] for page in pages}) == 1
    assert stored_counts(case) == before


def test_live_multisource_datasets_are_kept_as_observed_source_facts(
    case: Case, admin: Login
) -> None:
    records = [*seed_events(case, admin, 1), *seed_events(case, admin, 1)]
    assert (
        records[0].source_id != records[1].source_id
        and records[0].dataset_id != records[1].dataset_id
    )
    incident = investigate(admin, records)
    before = stored_counts(case)
    data = read(admin, incident)
    assert (
        data["mode"] == "live" and data["dataset_id"] is None and data["run_id"] == str(UUID(int=0))
    )
    assert {item["event_snapshot"]["source_id"] for item in data["items"]} == {
        str(item.source_id) for item in records
    }
    assert {item["event_snapshot"]["dataset_id"] for item in data["items"]} == {
        str(item.dataset_id) for item in records
    }
    assert data["total"] == 2 and stored_counts(case) == before


def test_replay_timeline_keeps_exact_dataset_and_run_with_identical_observed_values(
    case: Case, admin: Login
) -> None:
    first_scope, second_scope = (uuid4(), uuid4()), (uuid4(), uuid4())
    first = seed_events(case, admin, 1, replay=first_scope)
    second = seed_events(case, admin, 1, replay=second_scope)
    incident = investigate(admin, first)
    other = investigate(admin, second)
    before = stored_counts(case)
    for target, scope, record in (
        (incident, first_scope, first[0]),
        (other, second_scope, second[0]),
    ):
        data = read(admin, target)
        assert data["mode"] == "replay" and data["dataset_id"] == str(scope[0])
        assert data["run_id"] == str(scope[1]) and data["total"] == 1
        assert data["items"][0]["event_id"] == str(record.event_id)
    assert stored_counts(case) == before


@pytest.mark.parametrize("damage", ["mode", "dataset", "run"])
def test_corrupt_active_alert_scope_is_rejected_instead_of_silently_filtered(
    case: Case, admin: Login, damage: str
) -> None:
    records = seed_events(case, admin, 1, replay=(uuid4(), uuid4()))
    incident = investigate(admin, records)
    values = {"mode": "live", "dataset_id": uuid4(), "run_id": uuid4()}
    field = {"mode": "mode", "dataset": "dataset_id", "run": "run_id"}[damage]
    with case.database.owner.begin() as db:
        db.execute(text("ALTER TABLE alerts DISABLE TRIGGER USER"))
        db.execute(update(Alert).where(Alert.id == records[0].id).values(**{field: values[field]}))
        db.execute(text("ALTER TABLE alerts ENABLE TRIGGER USER"))
    before = stored_counts(case)
    result = response(admin, incident)
    assert (
        result.status_code == 409 and result.json()["code"] == "attack_timeline_integrity_mismatch"
    )
    assert stored_counts(case) == before


@pytest.mark.parametrize(
    "damage", ["raw_hash", "normalized_hash", "normalized_scope", "copy_rehashed"]
)
def test_selected_original_and_copied_event_proofs_fail_closed_even_when_rehashed(
    case: Case, admin: Login, damage: str
) -> None:
    record = seed_events(case, admin, 1)[0]
    incident = investigate(admin, [record])
    with Session(case.database.runtime) as db:
        normalized = db.get(NormalizedEvent, record.event_id)
        assert normalized is not None
        document = deepcopy(normalized.document)
    table = (
        "raw_events"
        if damage == "raw_hash"
        else "alerts"
        if damage == "copy_rehashed"
        else "normalized_events"
    )
    with case.database.owner.begin() as db:
        db.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER USER"))
        if damage == "raw_hash":
            db.execute(
                update(RawEvent).where(RawEvent.id == record.event_id).values(payload_hash="0" * 64)
            )
        elif damage == "normalized_hash":
            db.execute(
                update(NormalizedEvent)
                .where(NormalizedEvent.event_id == record.event_id)
                .values(document_sha256="0" * 64)
            )
        elif damage == "normalized_scope":
            document["source_id"] = str(uuid4())
            digest = hashlib.sha256(canonical_json(document)).hexdigest()
            db.execute(
                update(NormalizedEvent)
                .where(NormalizedEvent.event_id == record.event_id)
                .values(document=document, document_sha256=digest)
            )
            # Keep every copied document and reference hash mutually consistent.
            # Only the original RawEvent retains the authoritative source_id, so
            # failure must come from selected source verification rather than an
            # earlier copied/hash equality guard.
            db.execute(text("ALTER TABLE alerts DISABLE TRIGGER USER"))
            db.execute(text("ALTER TABLE alert_event_references DISABLE TRIGGER USER"))
            db.execute(
                update(Alert)
                .where(Alert.id == record.id)
                .values(event_snapshot=document, event_sha256=digest)
            )
            db.execute(
                update(AlertEventReference)
                .where(AlertEventReference.alert_id == record.id)
                .values(document_sha256=digest)
            )
            db.execute(text("ALTER TABLE alerts ENABLE TRIGGER USER"))
            db.execute(text("ALTER TABLE alert_event_references ENABLE TRIGGER USER"))
        else:
            document["process"]["command_line"] = "rehashed conflicting observed command"
            db.execute(
                update(Alert)
                .where(Alert.id == record.id)
                .values(
                    event_snapshot=document,
                    event_sha256=hashlib.sha256(canonical_json(document)).hexdigest(),
                )
            )
        db.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER USER"))
    before = stored_counts(case)
    result = response(admin, incident)
    assert (
        result.status_code == 409 and result.json()["code"] == "attack_timeline_integrity_mismatch"
    ), result.text
    assert "items" not in result.json() and stored_counts(case) == before


@pytest.mark.parametrize("damage", ["count", "hash", "foreign_event"])
def test_existing_corrupt_receipt_or_reference_never_becomes_pending_or_foreign_evidence(
    case: Case, admin: Login, damage: str
) -> None:
    records = seed_events(case, admin)
    incident = investigate(admin, [records[0]])
    table = "entity_alert_receipts" if damage == "count" else "alert_event_references"
    with case.database.owner.begin() as db:
        db.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER USER"))
        if damage == "count":
            db.execute(
                update(EntityAlertReceipt)
                .where(EntityAlertReceipt.alert_id == records[0].id)
                .values(contributor_count=2)
            )
        elif damage == "hash":
            db.execute(
                update(AlertEventReference)
                .where(AlertEventReference.alert_id == records[0].id)
                .values(document_sha256="0" * 64)
            )
        else:
            db.execute(
                update(AlertEventReference)
                .where(AlertEventReference.alert_id == records[0].id)
                .values(event_id=records[1].event_id, document_sha256=records[1].event_sha256)
            )
        db.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER USER"))
    before = stored_counts(case)
    result = response(admin, incident)
    assert (
        result.status_code == 409 and result.json()["code"] == "attack_timeline_integrity_mismatch"
    ), result.text
    assert "index_status" not in result.json() and stored_counts(case) == before


def duplicate_case(case: Case, admin: Login) -> tuple[dict[str, Any], list[Alert]]:
    digest = "c" * 64
    create_ioc(admin, digest, "hash", reputation="malicious", confidence=90)
    _, identifiers = normalize_inputs(case, admin, [hashed_powershell(digest)])
    detect_once(processing_database(case), case.database.settings)
    records = [item for item in alerts(case) if item.event_id == identifiers[0]]
    assert len(records) == 2
    return investigate(admin, records), records


def test_shared_event_keeps_both_immutable_alert_references_and_rejects_conflicting_copy(
    case: Case, admin: Login
) -> None:
    incident, records = duplicate_case(case, admin)
    data = read(admin, incident)
    assert data["total"] == len(data["items"]) == 1
    assert {row["id"] for row in data["items"][0]["alerts"]} == {str(item.id) for item in records}
    damaged = max(records, key=lambda item: item.id)
    document = deepcopy(damaged.event_snapshot)
    document["process"]["name"] = "conflicting-copy.exe"
    digest = hashlib.sha256(canonical_json(document)).hexdigest()
    copies = [
        {**item, "event_snapshot": document, "event_sha256": digest}
        for item in damaged.event_snapshots
    ]
    with case.database.owner.begin() as db:
        db.execute(text("ALTER TABLE alerts DISABLE TRIGGER USER"))
        db.execute(
            update(Alert)
            .where(Alert.id == damaged.id)
            .values(event_snapshot=document, event_sha256=digest, event_snapshots=copies)
        )
        db.execute(text("ALTER TABLE alerts ENABLE TRIGGER USER"))
    before = stored_counts(case)
    result = response(admin, incident)
    assert (
        result.status_code == 409 and result.json()["code"] == "attack_timeline_integrity_mismatch"
    )
    assert stored_counts(case) == before


def test_unindexed_legacy_is_honest_readonly_pending_and_backfill_changes_old_cursor(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    indexed = seed_events(case, admin)
    legacy = seed_events(case, admin, 1, legacy=True, monkeypatch=monkeypatch)
    incident = investigate(admin, [*indexed, *legacy])
    before = stored_counts(case)
    first = read(admin, incident, limit=1)
    assert first["index_status"] == {
        "eligible_alerts": 3,
        "indexed_alerts": 2,
        "pending_alerts": 1,
        "complete": False,
    }
    assert first["total"] == 2 and first["next_cursor"]
    repeated = read(admin, incident, limit=1)
    assert {key: value for key, value in repeated.items() if key != "next_cursor"} == {
        key: value for key, value in first.items() if key != "next_cursor"
    }
    assert repeated["next_cursor"] and stored_counts(case) == before
    backfill = admin.client.post(
        "/api/v1/entities/backfill", json={"limit": 100}, headers=admin.authorization
    )
    assert backfill.status_code == 200, backfill.text
    after = stored_counts(case)
    assert_changed(admin, incident, first["next_cursor"])
    fresh = read(admin, incident)
    assert fresh["incident_version"] == first["incident_version"]
    assert fresh["index_status"]["complete"] and fresh["total"] == 3
    assert fresh["view_fingerprint"] != first["view_fingerprint"]
    assert stored_counts(case) == after


def test_fp_is_retained_as_observation_and_changes_cursor_without_case_version_change(
    case: Case, admin: Login
) -> None:
    records = seed_events(case, admin)
    incident = investigate(admin, records)
    first = read(admin, incident, limit=1)
    result = admin.client.patch(
        f"/api/v1/alerts/{records[0].id}",
        json={"status": "false_positive"},
        headers={**admin.authorization, "If-Match": f'"{records[0].version}"'},
    )
    assert result.status_code == 200, result.text
    before = stored_counts(case)
    assert_changed(admin, incident, first["next_cursor"])
    fresh = read(admin, incident)
    assert fresh["total"] == 2 and fresh["incident_version"] == first["incident_version"]
    reference = next(
        reference
        for item in fresh["items"]
        for reference in item["alerts"]
        if reference["id"] == str(records[0].id)
    )
    assert reference["status"] == "false_positive"
    assert stored_counts(case) == before


def test_detach_reattach_and_late_old_event_attachment_invalidate_current_view_cursor(
    case: Case, admin: Login
) -> None:
    records = seed_events(case, admin)
    incident = investigate(admin, records)
    first = read(admin, incident, limit=1)
    original_linked = {
        item["id"]: item["linked_at"]
        for row in read(admin, incident)["items"]
        for item in row["alerts"]
    }
    incident = detach(admin, incident, records[1])
    detached = read(admin, incident)
    assert detached["total"] == 1 and all(
        reference["id"] != str(records[1].id)
        for row in detached["items"]
        for reference in row["alerts"]
    )
    incident = attach(admin, incident, records[1])
    assert_changed(admin, incident, first["next_cursor"])
    restored = read(admin, incident, limit=1)
    current_linked = {
        item["id"]: item["linked_at"]
        for row in read(admin, incident)["items"]
        for item in row["alerts"]
    }
    assert current_linked == original_linked
    old = seed_events(case, admin, 1, timestamps=[(START - timedelta(days=1)).isoformat()])[0]
    incident = attach(admin, incident, old)
    before = stored_counts(case)
    assert_changed(admin, incident, restored["next_cursor"])
    fresh = read(admin, incident)
    assert fresh["total"] == 3 and fresh["items"][0]["event_id"] == str(old.event_id)
    assert stored_counts(case) == before


def test_page_limits_unknown_cases_and_empty_case_are_readonly(case: Case, admin: Login) -> None:
    incident = investigate(admin, seed_events(case, admin))
    empty = investigate(admin, [])
    before = stored_counts(case)
    for limit in (0, -1, 26, "true", "1.5"):
        result = response(admin, incident, limit=limit)
        assert result.status_code == 422 and "items" not in result.json()
    assert response(admin, incident, cursor="x" * 4097).status_code == 422
    assert response(admin, {"id": str(uuid4())}).status_code == 404
    data = read(admin, empty)
    assert data["total"] == 0 and data["items"] == [] and data["next_cursor"] is None
    assert data["index_status"] == {
        "eligible_alerts": 0,
        "indexed_alerts": 0,
        "pending_alerts": 0,
        "complete": True,
    }
    assert stored_counts(case) == before


def test_untrusted_metadata_remains_observed_text_and_never_becomes_attack_annotation(
    case: Case, admin: Login
) -> None:
    payload = powershell()
    payload["raw_event"].update(
        {
            "attack_stage": "credential_access",
            "mitre_techniques": ["T1003"],
            "risk_score": 100,
            "confirmed_attack": True,
            "label": "<img src=x onerror=alert(1)>",
        }
    )
    _, identifiers = normalize_inputs(case, admin, [payload])
    detect_once(processing_database(case), case.database.settings)
    incident = investigate(admin, [item for item in alerts(case) if item.event_id in identifiers])
    before = stored_counts(case)
    data = read(admin, incident)
    item = data["items"][0]
    assert item["event_snapshot"]["raw_event"]["label"] == payload["raw_event"]["label"]
    assert not {
        "attack_stage",
        "mitre_techniques",
        "risk_score",
        "confirmed_attack",
        "stage",
        "mitre",
    }.intersection(item)
    assert stored_counts(case) == before


def test_real_valid_large_source_page_is_rejected_before_unbounded_materialization(
    case: Case, admin: Login
) -> None:
    create_ioc(admin, "192.0.2.1", "ip", reputation="malicious", confidence=90)
    padding = "".join(random.Random(2026).choices(string.ascii_letters + string.digits, k=65000))
    short = padding[:256]
    raw_fields = {
        "host": dict.fromkeys(("id", "name", "os"), short),
        "user": {
            **dict.fromkeys(("id", "name", "realm"), short),
            "target": dict.fromkeys(("id", "name", "realm"), short),
        },
        "session": dict.fromkeys(("id", "provider", "host_id", "boot_id"), short),
        "process": {
            **dict.fromkeys(("name", "entity_id", "parent_entity_id"), short),
            **dict.fromkeys(("executable", "hash"), padding[:1024]),
            "command_line": padding[:8192],
        },
        "file": {"name": short, "path": padding[:1024], "hash": padding[:1024]},
        "http": {
            "url": padding[:8192],
            "referrer": padding[:8192],
            "user_agent": padding[:1024],
            "request_method": short,
            "version": short,
        },
        "network": dict.fromkeys(("protocol", "transport"), short),
        "extensions": {"original_bounded_adapter_field": padding[:8000]},
        "padding": "",
    }
    inputs = []
    for index in range(25):
        payload = auth_event(START + timedelta(seconds=index), "success", **deepcopy(raw_fields))
        payload["raw_event"]["padding"] = padding[
            : 65000 - len(canonical_json(payload["raw_event"]))
        ]
        assert len(canonical_json(payload["raw_event"])) == 65000
        inputs.append(payload)
    # Preserve full-size source events while keeping each genuine ingestion
    # request below its independent 1 MiB transport limit.
    source = enroll(admin, source_types=["generic_json"])
    identifiers = []
    for offset in range(0, len(inputs), 10):
        _, batch_ids = normalize_inputs(case, admin, inputs[offset : offset + 10], source=source)
        identifiers.extend(batch_ids)
    detect_once(processing_database(case), case.database.settings)
    records = [item for item in alerts(case) if item.event_id in identifiers]
    assert len(records) == 25 and all(
        item.evaluator_version.startswith("intelligence-") for item in records
    )
    # Each bounded typed field appears in the normalized document in addition to
    # its original raw representation. This real page exceeds the returned-source
    # budget even when copied alert evidence is not included in that budget.
    with Session(case.database.runtime) as db:
        originals = list(
            db.scalars(select(NormalizedEvent).where(NormalizedEvent.event_id.in_(identifiers)))
        )
        assert sum(len(canonical_json(row.document)) + 65000 for row in originals) > 4 * 1024 * 1024
    incident = investigate(admin, records)
    before = stored_counts(case)
    large = response(admin, incident, limit=25)
    assert large.status_code == 409 and large.json()["code"] == "attack_timeline_page_too_large", (
        large.text[:500]
    )
    assert "items" not in large.json()
    small = read(admin, incident, limit=1)
    assert len(small["items"]) == 1 and small["total"] == 25 and small["next_cursor"]
    assert stored_counts(case) == before
