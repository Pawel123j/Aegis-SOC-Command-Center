"""Real PostgreSQL counters, deduplication and explicit operational scope."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.modules.dashboard.queries import dashboard
from app.modules.dashboard.schemas import DashboardFilters

from .helper_correlation import auth_event, normalize_inputs
from .helpers import Case, Login
from .test_initial_alerts import user
from .test_soar import source_alert

pytestmark = pytest.mark.integration
END = datetime(2026, 10, 2, tzinfo=UTC)


def read(principal: Login, **params: Any) -> dict[str, Any]:
    response = principal.client.get(
        "/api/v1/dashboard",
        headers=principal.authorization,
        params={"to": END.isoformat(), **params},
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    return dict(response.json())


def test_empty_is_zero_with_sixty_real_zero_buckets(admin: Login) -> None:
    report = read(admin)
    assert set(report["counts"].values()) == {0}
    assert all(not items for items in report["top"].values())
    assert not report["index_status"]["entities_partial"]
    assert len(report["ingestion"]["buckets"]) == 60
    assert all(row["count"] == 0 for row in report["ingestion"]["buckets"])
    assert report["scope"]["from"] == "2026-10-01T00:00:00Z"
    assert report["scope"]["to"] == "2026-10-02T00:00:00Z"


def test_true_event_window_and_ranks_count_unique_events(case: Case, admin: Login) -> None:
    normalize_inputs(
        case,
        admin,
        [
            auth_event(
                END - timedelta(hours=24),
                destination={"ip": "192.0.2.1"},
                user={"id": "same", "name": "alice", "target": {"id": "same", "name": "alice"}},
            ),
            auth_event(END - timedelta(seconds=1), destination={"ip": "198.51.100.4"}),
            auth_event(END),
            auth_event(END - timedelta(hours=24, microseconds=1)),
        ],
    )
    report = read(admin)
    assert report["counts"]["events_24h"] == 2
    assert report["counts"]["received_24h"] == 0  # Late events arrived today.
    assert report["top"]["hosts"][0]["count"] == 2
    assert report["top"]["source_ips"][0]["count"] == 2
    assert sum(row["count"] for row in report["top"]["users"]) == 2  # actor/target deduplicated
    assert len(report["top"]["destination_ips"]) == 2
    assert report["index_status"]["indexed_events"] == 2


def test_alerts_risk_and_false_positive_filter(case: Case, admin: Login) -> None:
    alert = source_alert(case, admin)
    report = read(admin)
    assert report["counts"]["alerts_24h"] == 1
    assert next(row for row in report["risk"] if row["id"] == "medium")["count"] == 1
    assert next(row for row in report["severity"] if row["id"] == "medium")["count"] == 1
    assert report["rules"][0]["id"] == "ti:malicious-indicator"
    with Session(case.database.owner) as db:
        db.execute(text("UPDATE alerts SET status='false_positive' WHERE id=:id"), {"id": alert.id})
        db.commit()
    report = read(admin)
    assert report["counts"]["alerts_24h"] == 0
    assert report["counts"]["excluded_false_positives"] == 1
    assert not report["rules"]
    included = read(admin, include_false_positives=True)
    assert included["counts"]["alerts_24h"] == 1
    assert included["counts"]["excluded_false_positives"] == 0


def test_live_and_exact_replay_never_mix(case: Case, admin: Login) -> None:
    dataset, run = uuid4(), uuid4()
    normalize_inputs(case, admin, [auth_event(END - timedelta(hours=1))])
    normalize_inputs(
        case,
        admin,
        [auth_event(END - timedelta(hours=1)), auth_event(END - timedelta(hours=2))],
        replay=(dataset, run),
    )
    assert read(admin)["counts"]["events_24h"] == 1
    result = read(admin, mode="replay", dataset_id=str(dataset), run_id=str(run))
    assert result["counts"]["events_24h"] == 2
    assert result["top"]["hosts"][0]["count"] == 2
    assert (
        read(admin, mode="replay", dataset_id=str(dataset), run_id=str(uuid4()))["counts"][
            "events_24h"
        ]
        == 0
    )


@pytest.mark.parametrize("role", ["read_only", "soc_analyst", "soc_manager"])
def test_read_roles_can_view_dashboard(case: Case, admin: Login, role: str) -> None:
    assert read(user(case, admin, role))["counts"]["events_24h"] == 0


def test_query_receipt_time_and_exact_rate_boundaries(case: Case, admin: Login) -> None:
    _, ids = normalize_inputs(case, admin, [auth_event(END - timedelta(hours=2)) for _ in range(5)])
    values = [
        END - timedelta(hours=1),
        END - timedelta(minutes=59),
        END - timedelta(microseconds=1),
        END,
        END - timedelta(hours=1, microseconds=1),
    ]
    with Session(case.database.owner) as db:
        for identifier, at in zip(ids, values, strict=True):
            db.execute(
                text("UPDATE raw_events SET received_at=:at WHERE id=:id"),
                {"at": at, "id": identifier},
            )
        db.commit()
    with Session(case.database.runtime) as db:
        report = dashboard(db, DashboardFilters(to=END), END + timedelta(seconds=1))
    assert report.counts.received_24h == 4
    assert report.ingestion.accepted_events == 3
    assert report.ingestion.average_eps == 3 / 3600
    assert [row.count for row in report.ingestion.buckets[:2]] == [1, 1]
    assert report.ingestion.buckets[-1].count == 1


@pytest.mark.parametrize(
    "params",
    [
        {"mode": "replay"},
        {"dataset_id": str(uuid4())},
        {"to": "2026-10-02T00:00:00"},
        {"to": "2026-10-02T00:00:00+02:00"},
        {"to": "2200-01-01T00:00:00Z"},
        {"mode": "live' OR 1=1--"},
        {"unknown": "value"},
    ],
)
def test_invalid_scope_or_time_is_rejected(admin: Login, params: dict[str, Any]) -> None:
    response = admin.client.get("/api/v1/dashboard", headers=admin.authorization, params=params)
    assert response.status_code == 422


def test_pending_entity_indexes_are_explicit_and_reads_never_backfill(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    from .helper_entities import counts

    with monkeypatch.context() as patch:
        patch.setattr("app.modules.normalization.processing.index_event", lambda *a, **k: 0)
        normalize_inputs(case, admin, [auth_event(END - timedelta(hours=1))])
    before = counts(case)
    for _ in range(2):
        result = read(admin)
        assert result["counts"]["events_24h"] == 1
        assert result["index_status"] == {
            "pending_events": 1,
            "indexed_events": 0,
            "entities_partial": True,
        }
        assert all(not rows for rows in result["top"].values())
    assert counts(case) == before


@pytest.mark.parametrize("damage", ["hash", "count", "scope"])
def test_inconsistent_entity_index_fails_closed(case: Case, admin: Login, damage: str) -> None:
    normalize_inputs(case, admin, [auth_event(END - timedelta(hours=1))])
    table = "entity_identities" if damage == "scope" else "entity_index_receipts"
    statement = {
        "hash": "UPDATE entity_index_receipts SET document_sha256=repeat('a',64)",
        "count": "UPDATE entity_index_receipts SET observation_count=observation_count+1",
        "scope": "UPDATE entity_identities SET mode='replay',dataset_id=:dataset,run_id=:run",
    }[damage]
    with Session(case.database.owner) as db:
        db.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER USER"))
        db.execute(text(statement), {"dataset": uuid4(), "run": uuid4()})
        db.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER USER"))
        db.commit()
    response = admin.client.get(
        "/api/v1/dashboard", headers=admin.authorization, params={"to": END.isoformat()}
    )
    assert response.status_code == 409
    assert response.json()["code"] == "dashboard_index_integrity"
    assert "counts" not in response.json()


def test_entity_top_ten_is_stable_and_uses_ids_for_ties(case: Case, admin: Login) -> None:
    normalize_inputs(
        case,
        admin,
        [auth_event(END - timedelta(hours=1), source={"ip": f"192.0.2.{i}"}) for i in range(1, 14)],
    )
    first = read(admin)["top"]["source_ips"]
    assert len(first) == 10
    assert [item["id"] for item in first] == sorted(item["id"] for item in first)
    assert all(item["count"] == 1 for item in first)
    assert read(admin)["top"]["source_ips"] == first


def test_cases_are_current_open_all_time_and_scope_isolated(case: Case, admin: Login) -> None:
    from .test_incidents import create

    first = create(admin, severity="critical")
    second = create(admin, severity="high")
    third = create(admin, severity="critical")
    dataset, run = uuid4(), uuid4()
    create(admin, severity="critical", mode="replay", dataset_id=str(dataset), run_id=str(run))
    with Session(case.database.owner) as db:
        db.execute(text("UPDATE incidents SET created_at=:at"), {"at": END - timedelta(days=90)})
        db.execute(
            text("UPDATE incidents SET status='contained' WHERE id=:id"), {"id": first["id"]}
        )
        db.execute(
            text("UPDATE incidents SET status='investigating' WHERE id=:id"), {"id": second["id"]}
        )
        db.execute(text("UPDATE incidents SET status='resolved' WHERE id=:id"), {"id": third["id"]})
        db.commit()
    result = read(admin)
    assert result["counts"]["open_incidents"] == 2
    assert result["counts"]["critical_incidents"] == 1
    assert result["scope"]["incident_basis"] == "current_open_cases_all_time"
    assert (
        read(admin, mode="replay", dataset_id=str(dataset), run_id=str(run))["counts"][
            "open_incidents"
        ]
        == 1
    )


def test_tactics_count_alerts_once_and_preserve_unassessed_risk(case: Case, admin: Login) -> None:
    from app.modules.mitre.models import AlertMitreMapping

    from .helper_ingestion import processing_database
    from .test_initial_alerts import alerts, detect_once, normalize_events, powershell

    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    alert = alerts(case)[0]
    with Session(case.database.owner) as db:
        # Detection already froze the MITRE snapshot and its normalized rows
        # (PowerShell -> T1059.001 / TA0002); inserting the same row again would
        # violate the primary key, and other techniques are rejected by the
        # snapshot trigger. Assert the recorded mapping instead.
        mapped = db.scalars(
            select(AlertMitreMapping.tactic_id).where(AlertMitreMapping.alert_id == alert.id)
        ).all()
        assert "TA0002" in mapped
        db.execute(
            text(
                "UPDATE alerts SET risk_score=NULL,risk_level=NULL,risk_calculation_id=NULL "
                "WHERE id=:id"
            ),
            {"id": alert.id},
        )
        db.commit()
    result = read(admin)
    assert result["tactics"] == [{"id": "TA0002", "label": "Execution", "count": 1}]
    assert result["mitre_status"]["mapped_alerts"] == 1
    assert next(row for row in result["risk"] if row["id"] == "unassessed")["count"] == 1
    assert sum(row["count"] for row in result["severity"]) == 1


@pytest.mark.parametrize(
    "missing", ["events:read", "alerts:read", "incidents:read", "detections:read"]
)
def test_each_read_permission_is_required(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    from app.core import permissions
    from app.core.permissions import Permission, Role

    principal = user(case, admin, "read_only")
    restricted = dict(permissions.ROLE_PERMISSIONS)
    restricted[Role.READ_ONLY] = restricted[Role.READ_ONLY] - {Permission(missing)}
    monkeypatch.setattr(permissions, "ROLE_PERMISSIONS", restricted)
    response = principal.client.get("/api/v1/dashboard", headers=principal.authorization)
    assert response.status_code == 403
    assert response.headers["cache-control"] == "no-store"
    assert "counts" not in response.json()


def test_anonymous_and_source_credentials_cannot_read(case: Case, admin: Login) -> None:
    from .helper_ingestion import enroll

    for headers in ({}, enroll(admin).authorization):
        response = case.client().get("/api/v1/dashboard", headers=headers)
        assert response.status_code == 401
        assert response.headers["cache-control"] == "no-store"


def test_dashboard_polling_is_rate_limited(admin: Login) -> None:
    for _ in range(30):
        read(admin)
    response = admin.client.get("/api/v1/dashboard", headers=admin.authorization)
    assert response.status_code == 429
