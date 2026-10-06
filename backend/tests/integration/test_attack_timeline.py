"""Observed chronology from real ingestion, immutable alert proof and active links."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.modules.alerts.models import Alert
from app.modules.correlation.processing import process_once as correlate_once
from app.modules.detections import processing
from app.modules.entities import indexing

from .helper_attack_timeline import create, read, seed
from .helper_correlation import auth_sequence, normalize_inputs, seal
from .helper_ingestion import processing_database
from .helper_sigma import definition, import_rule, publish
from .helpers import Case, Login
from .test_initial_alerts import alerts, powershell

pytestmark = pytest.mark.integration


def domain_counts(case: Case) -> dict[str, int]:
    with Session(case.database.runtime) as db:
        return {
            name: int(db.scalar(text(f"SELECT count(*) FROM {name}")) or 0)
            for name in (
                "raw_events",
                "normalized_events",
                "alerts",
                "incidents",
                "incident_alerts",
                "incident_timeline",
                "entity_alert_receipts",
                "alert_event_references",
                "risk_calculations",
                "int_event_receipts",
                "audit_logs",
            )
        }


def test_empty_manual_case_is_complete_without_invented_events(case: Case, admin: Login) -> None:
    incident = create(admin)
    before = domain_counts(case)
    result = read(admin, incident["id"])
    assert result["incident_id"] == incident["id"]
    assert result["incident_version"] == incident["version"]
    assert result["mode"] == "live" and result["dataset_id"] is None
    assert result["run_id"] == str(UUID(int=0))
    assert result["projection_version"] == "attack-timeline-v1"
    assert len(result["view_fingerprint"]) == 64
    assert result["total"] == 0 and result["items"] == [] and result["next_cursor"] is None
    assert result["index_status"] == {
        "eligible_alerts": 0,
        "indexed_alerts": 0,
        "pending_alerts": 0,
        "complete": True,
    }
    assert domain_counts(case) == before


def test_original_snapshot_and_current_reference_are_returned_without_recalculation(
    case: Case, admin: Login
) -> None:
    identities = seed(case, admin, [powershell()])
    incident = create(admin, alert_ids=[str(row) for row in identities])
    record = alerts(case)[0]
    before = domain_counts(case)
    result = read(admin, incident["id"])
    item = result["items"][0]
    assert item["event_id"] == str(record.event_id)
    assert item["event_sha256"] == record.event_sha256
    assert item["event_snapshot"] == record.event_snapshot
    assert item["alerts"][0] == {
        "id": str(record.id),
        "title": record.title,
        "severity": record.severity,
        "status": record.status,
        "detection_type": "single_event",
        "rule_id": record.rule_id,
        "rule_version": record.rule_version,
        "linked_at": item["alerts"][0]["linked_at"],
    }
    assert set(item) == {"event_id", "event_sha256", "event_snapshot", "alerts"}
    assert result["total"] == 1 and result["next_cursor"] is None
    assert domain_counts(case) == before


def test_event_time_pages_are_ascending_and_same_time_uses_uuid_tie(
    case: Case, admin: Login
) -> None:
    events = [
        dict(powershell(), timestamp=value)
        for value in (
            "2026-10-01T12:02:00Z",
            "2026-10-01T12:00:00.123456Z",
            "2026-10-01T12:00:00.123456Z",
            "2026-10-01T12:01:00Z",
        )
    ]
    identities = seed(case, admin, events)
    incident = create(admin, alert_ids=[str(row) for row in reversed(identities)])
    keys, fingerprints = [], set()
    params: dict[str, Any] = {"limit": 1}
    for _ in range(4):
        result = read(admin, incident["id"], **params)
        assert result["total"] == 4 and len(result["items"]) == 1
        row = result["items"][0]
        keys.append((row["event_snapshot"]["timestamp"], row["event_id"]))
        fingerprints.add(result["view_fingerprint"])
        params["cursor"] = result["next_cursor"]
    assert params["cursor"] is None and keys == sorted(keys)
    assert len({key[1] for key in keys}) == 4 and len(fingerprints) == 1


def test_shared_sigma_and_builtin_event_is_deduplicated_and_fp_is_retained(
    case: Case, admin: Login
) -> None:
    publish(
        admin,
        import_rule(
            admin,
            definition(
                detection={
                    "selection": {"CommandLine|contains": "EncodedCommand"},
                    "condition": "selection",
                }
            ),
        ),
    )
    identities = seed(case, admin, [powershell()])
    assert len(identities) == 2
    incident = create(admin, alert_ids=[str(row) for row in identities])
    changed = admin.client.patch(
        f"/api/v1/alerts/{identities[0]}",
        json={"status": "false_positive"},
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert changed.status_code == 200, changed.text
    result = read(admin, incident["id"])
    assert result["total"] == 1 and len(result["items"]) == 1
    references = result["items"][0]["alerts"]
    assert {row["detection_type"] for row in references} == {"sigma", "single_event"}
    assert {row["status"] for row in references} == {"new", "false_positive"}
    assert {row["id"] for row in references} == {str(row) for row in identities}


def test_multi_alert_replay_contributors_include_nonanchor_and_preserve_exact_scope(
    case: Case, admin: Login
) -> None:
    scope = uuid4(), uuid4()
    _, ids = normalize_inputs(
        case, admin, auth_sequence(datetime(2026, 10, 1, 12, tzinfo=UTC)), replay=scope
    )
    seal(admin, scope, len(ids))
    correlate_once(processing_database(case), case.database.settings)
    records = alerts(case)
    assert len(records) == 2 and all(record.event_id != ids[0] for record in records)
    incident = create(
        admin,
        mode="replay",
        dataset_id=str(scope[0]),
        run_id=str(scope[1]),
        alert_ids=[str(record.id) for record in records],
    )
    result = read(admin, incident["id"])
    assert result["total"] == 6 and len(result["items"]) == 6
    assert [row["event_id"] for row in result["items"]] == [str(row) for row in ids]
    assert len(result["items"][0]["alerts"]) == 2
    assert len(result["items"][-1]["alerts"]) == 1
    assert result["mode"] == "replay" and result["dataset_id"] == str(scope[0])
    assert result["run_id"] == str(scope[1])
    assert all(row["event_snapshot"]["run_id"] == str(scope[1]) for row in result["items"])


def test_legacy_missing_index_is_pending_and_get_does_not_write(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    with monkeypatch.context() as legacy:
        legacy.setattr(processing, "index_alert", lambda *_: None)
        identities = seed(case, admin, [powershell()])
    incident = create(admin, alert_ids=[str(row) for row in identities])
    before = domain_counts(case)
    pending = read(admin, incident["id"])
    assert pending["total"] == 0 and pending["items"] == []
    assert pending["index_status"] == {
        "eligible_alerts": 1,
        "indexed_alerts": 0,
        "pending_alerts": 1,
        "complete": False,
    }
    assert domain_counts(case) == before
    with Session(case.database.runtime) as db:
        record = db.get(Alert, identities[0])
        assert record is not None
        indexing.index_alert(db, record)
        db.commit()
    complete = read(admin, incident["id"])
    assert complete["total"] == 1 and complete["index_status"]["complete"]
    assert complete["view_fingerprint"] != pending["view_fingerprint"]


def test_detached_alert_is_excluded_while_existing_history_keeps_it(
    case: Case, admin: Login
) -> None:
    identities = seed(case, admin, [powershell()])
    incident = create(admin, alert_ids=[str(row) for row in identities])
    original = read(admin, incident["id"])
    detached = admin.client.delete(
        f"/api/v1/incidents/{incident['id']}/alerts/{identities[0]}",
        headers={**admin.authorization, "If-Match": f'"{incident["version"]}"'},
    )
    assert detached.status_code == 200, detached.text
    result = read(admin, incident["id"])
    assert result["total"] == 0 and result["index_status"]["eligible_alerts"] == 0
    assert result["view_fingerprint"] != original["view_fingerprint"]
    history = admin.client.get(
        f"/api/v1/incidents/{incident['id']}/evidence", headers=admin.authorization
    )
    assert history.status_code == 200 and history.json()["total"] == 1
    assert history.json()["items"][0]["active"] is False


@pytest.mark.parametrize("query", [{"limit": 0}, {"limit": 26}, {"include_detached": "true"}])
def test_query_bounds_are_explicit(admin: Login, query: dict[str, Any]) -> None:
    response = admin.client.get(
        f"/api/v1/incidents/{uuid4()}/attack-timeline", params=query, headers=admin.authorization
    )
    assert response.status_code == 422


def test_missing_incident_is_not_a_complete_empty_case(admin: Login) -> None:
    response = admin.client.get(
        f"/api/v1/incidents/{uuid4()}/attack-timeline", headers=admin.authorization
    )
    assert response.status_code == 404 and response.json()["code"] == "incident_not_found"
