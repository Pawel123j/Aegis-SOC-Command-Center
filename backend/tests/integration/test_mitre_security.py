"""Independent scope, authority, source-proof and append-only MITRE checks."""

import hashlib
from copy import deepcopy
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core import permissions
from app.core.permissions import Permission, Role
from app.infrastructure.database import utcnow
from app.modules.alerts.models import Alert
from app.modules.audit.models import AuditLog
from app.modules.auth.models import AuthSession
from app.modules.incidents.models import Incident, IncidentAlert, IncidentTimeline
from app.modules.ingestion.schemas import canonical_json
from app.modules.mitre.models import AlertMitreMapping, AlertMitreSnapshot
from app.modules.risk.models import RiskCalculation
from app.modules.users.models import User

from .helper_correlation import normalize_inputs
from .helper_ingestion import enroll, processing_database
from .helpers import Case, Login, migrate
from .test_incidents import create
from .test_initial_alerts import alerts, detect_once, normalize_events, powershell, user

pytestmark = pytest.mark.integration
CATALOG = "/api/v1/mitre/catalog"
COVERAGE = "/api/v1/mitre/coverage"


def view(principal: Login, **params: Any) -> dict[str, Any]:
    response = principal.client.get(COVERAGE, params=params, headers=principal.authorization)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    return dict(response.json())


def signals(case: Case, admin: Login, count: int = 1) -> list[Alert]:
    normalize_events(case, admin, [powershell() for _ in range(count)])
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == count
    records = alerts(case)
    assert len(records) == count
    return records


def domain_counts(case: Case) -> dict[str, int]:
    with Session(case.database.runtime) as db:
        return {
            model.__tablename__: int(db.scalar(select(func.count()).select_from(model)) or 0)
            for model in (
                Alert,
                Incident,
                IncidentAlert,
                IncidentTimeline,
                RiskCalculation,
                AlertMitreSnapshot,
                AlertMitreMapping,
                AuditLog,
            )
        }


@pytest.mark.parametrize("role", ["admin", "soc_manager", "soc_analyst", "read_only"])
def test_each_documented_read_role_can_use_candidate_catalogue_and_coverage(
    case: Case, admin: Login, role: str
) -> None:
    principal = admin if role == "admin" else user(case, admin, role)
    before = domain_counts(case)
    catalogue = principal.client.get(CATALOG, headers=principal.authorization)
    assert catalogue.status_code == 200
    assert catalogue.headers["cache-control"] == "no-store"
    assert len(catalogue.json()["techniques"]) == 697
    coverage = view(principal)
    assert coverage["claim"] == "candidate_association"
    assert coverage["confirmed_attack"] is False
    assert coverage["summary"]["eligible_alerts"] == 0
    assert domain_counts(case) == before


@pytest.mark.parametrize(
    "missing", [Permission.DETECTIONS_READ, Permission.ALERTS_READ, Permission.INCIDENTS_READ]
)
def test_coverage_requires_each_of_all_three_permissions(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch, missing: Permission
) -> None:
    principal = user(case, admin, "read_only")
    restricted = dict(permissions.ROLE_PERMISSIONS)
    restricted[Role.READ_ONLY] = restricted[Role.READ_ONLY] - {missing}
    monkeypatch.setattr(permissions, "ROLE_PERMISSIONS", restricted)
    response = principal.client.get(COVERAGE, headers=principal.authorization)
    assert response.status_code == 403
    assert response.headers["cache-control"] == "no-store"
    assert "techniques" not in response.json()
    # The catalogue itself requires only detections:read, so denial must be specific.
    catalogue = principal.client.get(CATALOG, headers=principal.authorization)
    assert catalogue.status_code == (403 if missing == Permission.DETECTIONS_READ else 200)


@pytest.mark.parametrize("path", [CATALOG, COVERAGE])
def test_anonymous_and_source_credentials_cannot_read_soc_mitre_data(
    case: Case, admin: Login, path: str
) -> None:
    source = enroll(admin)
    for headers in ({}, source.authorization):
        response = case.client().get(path, headers=headers)
        assert response.status_code == 401
        assert response.headers["cache-control"] == "no-store"
        assert "techniques" not in response.json()


@pytest.mark.parametrize("path", [CATALOG, COVERAGE])
@pytest.mark.parametrize("change", ["disabled", "revoked", "expired"])
def test_mitre_reads_reject_current_disabled_or_invalid_session(
    case: Case, admin: Login, path: str, change: str
) -> None:
    principal = user(case, admin, "read_only")
    with Session(case.database.owner) as db:
        if change == "disabled":
            db.execute(update(User).where(User.id == UUID(principal.user_id)).values(enabled=False))
        else:
            values = (
                {"revoked_at": utcnow()}
                if change == "revoked"
                else {"absolute_expires_at": utcnow() - timedelta(seconds=1)}
            )
            db.execute(
                update(AuthSession)
                .where(AuthSession.user_id == UUID(principal.user_id))
                .values(**values)
            )
        db.commit()
    response = principal.client.get(path, headers=principal.authorization)
    assert response.status_code == 401
    assert "techniques" not in response.json()


@pytest.mark.parametrize(
    "params",
    [
        {"mode": "replay"},
        {"mode": "replay", "dataset_id": str(UUID(int=1))},
        {"mode": "replay", "dataset_id": str(UUID(int=1)), "run_id": str(UUID(int=0))},
        {"mode": "live", "dataset_id": str(UUID(int=1))},
        {"mode": "live", "run_id": str(UUID(int=1))},
        {"from": "2000-01-01T00:00:00"},
        {"to": "2000-01-01T01:00:00+01:00"},
        {"from": "2000-01-01T00:00:00Z", "to": "2000-01-01T00:00:00Z"},
        {"from": "2000-01-02T00:00:00Z", "to": "2000-01-01T00:00:00Z"},
        {"from": "2000-01-01T00:00:00Z", "to": "2002-01-01T00:00:00Z"},
        {"to": "3000-01-01T00:00:00Z"},
        {"technique_id": "T1059.001 OR 1=1"},
    ],
)
def test_http_coverage_rejects_ambiguous_scopes_and_invalid_windows_without_writes(
    case: Case, admin: Login, params: dict[str, str]
) -> None:
    before = domain_counts(case)
    response = admin.client.get(COVERAGE, params=params, headers=admin.authorization)
    assert response.status_code == 422
    assert response.headers["cache-control"] == "no-store"
    assert "summary" not in response.json()
    assert domain_counts(case) == before


def test_coverage_counts_original_event_time_in_half_open_window_not_creation_time(
    case: Case, admin: Login
) -> None:
    start = utcnow() - timedelta(days=1, hours=1)
    end = start + timedelta(hours=1)
    times = [
        start - timedelta(microseconds=1),
        start,
        start + timedelta(microseconds=1),
        end - timedelta(microseconds=1),
        end,
        end + timedelta(microseconds=1),
    ]
    events = [dict(powershell(), timestamp=timestamp.isoformat()) for timestamp in times]
    normalize_inputs(case, admin, events)
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 6
    records = alerts(case)
    assert all(record.created_at > end for record in records)
    result = view(admin, **{"from": start.isoformat(), "to": end.isoformat()})
    assert result["scope"]["time_basis"] == "alert.event_timestamp"
    assert result["scope"]["interval"] == "[from,to)"
    assert result["summary"]["eligible_alerts"] == result["summary"]["mapped_alerts"] == 3
    assert result["summary"]["incidents"] == 3
    technique = next(row for row in result["techniques"] if row["id"] == "T1059.001")
    assert technique["alert_count"] == technique["incident_count"] == 3
    before = domain_counts(case)
    assert view(admin, **{"from": start.isoformat(), "to": end.isoformat()}) == result
    assert domain_counts(case) == before


def test_live_and_exact_replay_dataset_run_counts_stay_isolated(case: Case, admin: Login) -> None:
    dataset, run = uuid4(), uuid4()
    scopes = [None, (dataset, run), (dataset, uuid4()), (uuid4(), run)]
    for scope in scopes:
        normalize_inputs(
            case,
            admin,
            [dict(powershell(), timestamp=(utcnow() - timedelta(minutes=1)).isoformat())],
            replay=scope,
        )
        assert detect_once(processing_database(case), case.database.settings)["alerts"] == 1
    assert len(alerts(case)) == 4
    live = view(admin)
    assert live["summary"]["eligible_alerts"] == live["summary"]["incidents"] == 1
    for scope in scopes[1:]:
        assert scope is not None
        result = view(admin, mode="replay", dataset_id=str(scope[0]), run_id=str(scope[1]))
        assert result["scope"]["dataset_id"] == str(scope[0])
        assert result["scope"]["run_id"] == str(scope[1])
        assert result["summary"]["eligible_alerts"] == result["summary"]["incidents"] == 1
    empty = view(admin, mode="replay", dataset_id=str(uuid4()), run_id=str(uuid4()))
    assert empty["summary"]["eligible_alerts"] == empty["summary"]["incidents"] == 0


def test_detached_and_false_positive_links_do_not_inflate_current_case_coverage(
    case: Case, admin: Login
) -> None:
    records = signals(case, admin, 2)
    combined = create(admin, alert_ids=[str(record.id) for record in records])
    assert view(admin)["summary"]["incidents"] == 3
    with Session(case.database.runtime) as db:
        frozen = {
            row.alert_id: deepcopy(row.document) for row in db.scalars(select(AlertMitreSnapshot))
        }
    path = f"/api/v1/incidents/{combined['id']}"
    for record in records:
        response = admin.client.delete(
            f"{path}/alerts/{record.id}",
            headers={**admin.authorization, "If-Match": f'"{combined["version"]}"'},
        )
        assert response.status_code == 200, response.text
        combined = response.json()
    assert combined["evidence_count"] == 2
    assert combined["mitre_mapping"]["mapped_alerts"] == 0
    assert combined["mitre_mapping"]["techniques"] == []
    after_detach = view(admin)
    assert after_detach["summary"]["eligible_alerts"] == 2
    assert after_detach["summary"]["incidents"] == 2
    response = admin.client.patch(
        f"/api/v1/alerts/{records[0].id}",
        json={"status": "false_positive"},
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert response.status_code == 200, response.text
    assert response.json()["mitre_mapping"]["status"] == "mapped"
    default = view(admin)
    included = view(admin, include_false_positives="true")
    assert default["summary"]["eligible_alerts"] == default["summary"]["incidents"] == 1
    assert default["summary"]["excluded_false_positive_alerts"] == 1
    assert included["summary"]["eligible_alerts"] == included["summary"]["incidents"] == 2
    assert included["summary"]["excluded_false_positive_alerts"] == 0
    for result, count in ((default, 1), (included, 2)):
        technique = next(row for row in result["techniques"] if row["id"] == "T1059.001")
        assert technique["alert_count"] == technique["incident_count"] == count
    with Session(case.database.runtime) as db:
        assert {
            row.alert_id: row.document for row in db.scalars(select(AlertMitreSnapshot))
        } == frozen
        assert (
            db.scalar(
                select(func.count())
                .select_from(IncidentAlert)
                .where(
                    IncidentAlert.incident_id == UUID(combined["id"]),
                    IncidentAlert.active.is_(False),
                )
            )
            == 2
        )


def test_resolved_alert_and_closed_case_remain_historical_observations(
    case: Case, admin: Login
) -> None:
    record = signals(case, admin)[0]
    with Session(case.database.runtime) as db:
        incident = db.scalar(select(Incident).where(Incident.automatic_alert_id == record.id))
        assert incident is not None
        identifier = str(incident.id)
        version = incident.version
    response = admin.client.patch(
        f"/api/v1/alerts/{record.id}",
        json={"status": "resolved"},
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert response.status_code == 200, response.text
    for disposition in ("resolved", "closed"):
        response = admin.client.patch(
            f"/api/v1/incidents/{identifier}",
            json={"status": disposition, "status_reason": "Independent history retention test"},
            headers={**admin.authorization, "If-Match": f'"{version}"'},
        )
        assert response.status_code == 200, response.text
        version = response.json()["version"]
    result = view(admin)
    assert result["summary"]["eligible_alerts"] == result["summary"]["incidents"] == 1
    assert response.json()["mitre_mapping"]["mapped_alerts"] == 1


@pytest.mark.parametrize("change", ["event_time", "scope", "severity"])
def test_alert_reads_fail_closed_when_source_anchor_or_scope_is_corrupted(
    case: Case, admin: Login, change: str
) -> None:
    record = signals(case, admin)[0]
    values: dict[str, Any] = {
        "event_time": {"event_timestamp": record.event_timestamp + timedelta(seconds=1)},
        "scope": {"mode": "replay", "run_id": uuid4()},
        "severity": {"severity": "critical"},
    }[change]
    # Only the owner of this generated database can change immutable evidence columns.
    with Session(case.database.owner) as db:
        db.execute(update(Alert).where(Alert.id == record.id).values(**values))
        db.commit()
    before = domain_counts(case)
    response = admin.client.get(f"/api/v1/alerts/{record.id}", headers=admin.authorization)
    assert response.status_code == 409
    assert response.json()["code"] == "mitre_evidence_integrity_mismatch"
    assert domain_counts(case) == before


@pytest.mark.parametrize("change", ["digest", "name", "tactic", "url"])
def test_alert_and_case_reads_reject_changed_frozen_reference_even_with_rehashed_document(
    case: Case, admin: Login, change: str
) -> None:
    record = signals(case, admin)[0]
    with Session(case.database.owner) as db:
        row = db.get(AlertMitreSnapshot, record.id)
        assert row is not None
        document = deepcopy(row.document)
        if change == "digest":
            row.snapshot_sha256 = "0" * 64
        else:
            technique = document["techniques"][0]
            if change == "name":
                technique["name"] = "Different official-looking label"
            elif change == "tactic":
                technique["tactics"][0]["id"] = "TA0003"
            else:
                technique["url"] = "javascript:alert(1)"
            row.document = document
            row.snapshot_sha256 = hashlib.sha256(canonical_json(document)).hexdigest()
        incident = db.scalar(select(Incident).where(Incident.automatic_alert_id == record.id))
        assert incident is not None
        identifier = incident.id
        db.commit()
    before = domain_counts(case)
    for path in (f"/api/v1/alerts/{record.id}", f"/api/v1/incidents/{identifier}"):
        response = admin.client.get(path, headers=admin.authorization)
        assert response.status_code == 409
        assert response.json()["code"] == "mitre_snapshot_integrity_mismatch"
    assert domain_counts(case) == before


@pytest.mark.parametrize("table", ["alert_mitre_snapshots", "alert_mitre_mappings"])
@pytest.mark.parametrize("operation", ["UPDATE", "DELETE", "TRUNCATE"])
def test_runtime_can_append_but_cannot_rewrite_or_erase_committed_mitre_history(
    case: Case, admin: Login, table: str, operation: str
) -> None:
    signals(case, admin)
    before = domain_counts(case)
    statement = {
        "UPDATE": f"UPDATE {table} SET alert_id = alert_id",
        "DELETE": f"DELETE FROM {table}",
        "TRUNCATE": f"TRUNCATE {table}",
    }[operation]
    with case.database.runtime.connect() as db:
        assert db.scalar(
            text("SELECT has_table_privilege(current_user,:table,'SELECT')"), {"table": table}
        )
        assert db.scalar(
            text("SELECT has_table_privilege(current_user,:table,'INSERT')"), {"table": table}
        )
        db.rollback()
        with pytest.raises(DBAPIError) as rejected:
            db.execute(text(statement))
        assert getattr(rejected.value.orig, "sqlstate", None) == "42501"
        db.rollback()
    assert domain_counts(case) == before


@pytest.mark.parametrize("technique,tactic", [("T1059.001", "TA0003"), ("T9999", "TA0002")])
def test_runtime_normalized_association_cannot_disagree_with_its_frozen_parent(
    case: Case, admin: Login, technique: str, tactic: str
) -> None:
    record = signals(case, admin)[0]
    before = domain_counts(case)
    with case.database.runtime.connect() as db:
        with pytest.raises(DBAPIError) as rejected:
            db.execute(
                text(
                    "INSERT INTO alert_mitre_mappings(alert_id,technique_id,tactic_id) "
                    "VALUES (:alert,:technique,:tactic)"
                ),
                {"alert": record.id, "technique": technique, "tactic": tactic},
            )
        assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
        db.rollback()
    assert domain_counts(case) == before


def test_owner_downgrade_refuses_to_destroy_nonempty_mitre_history(
    case: Case, admin: Login
) -> None:
    record = signals(case, admin)[0]
    before = domain_counts(case)
    with pytest.raises(DBAPIError) as rejected:
        migrate(case.database.owner, "0007_risk", downgrade=True)
    assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
    assert domain_counts(case) == before
    with case.database.runtime.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "0009_sigma"
    response = admin.client.get(f"/api/v1/alerts/{record.id}", headers=admin.authorization)
    assert response.status_code == 200
    assert response.json()["mitre_mapping"]["status"] == "mapped"
