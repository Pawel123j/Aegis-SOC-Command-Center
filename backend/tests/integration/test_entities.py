"""Real immutable indexing, scope-specific activity and transparent alert projections."""

import hashlib
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.modules.correlation.processing import process_once as correlate_once
from app.modules.detections.processing import process_once as detect_once
from app.modules.entities import indexing
from app.modules.entities.models import EntityIndexReceipt, EntityObservation
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.models import NormalizedEvent
from app.modules.risk.models import RiskCalculation

from .helper_correlation import auth_event, auth_sequence, normalize_inputs, seal
from .helper_entities import WINDOW, counts, read
from .helper_ingestion import processing_database
from .helper_sigma import definition, import_rule, publish
from .helpers import Case, Login
from .test_initial_alerts import alerts, normalize_events, powershell

pytestmark = pytest.mark.integration
START = datetime(2026, 10, 1, 12, tzinfo=UTC)


def backfill(admin: Login, limit: int = 100) -> dict[str, Any]:
    result = admin.client.post(
        "/api/v1/entities/backfill", json={"limit": limit}, headers=admin.authorization
    )
    assert result.status_code == 200, result.text
    assert result.headers["cache-control"] == "no-store"
    return dict(result.json())


def test_normalization_atomically_indexes_observations_and_retry_is_read_only(
    case: Case,
    admin: Login,
) -> None:
    ids = normalize_events(case, admin, [powershell()])
    before = counts(case)
    assert before["entity_index_receipts"] == 1
    assert before["entity_identities"] == 3
    assert before["entity_observations"] == 3
    with Session(case.database.runtime) as db:
        snapshot = db.get(NormalizedEvent, ids[0])
        assert snapshot is not None and indexing.index_event(db, snapshot) == 0
        db.commit()
        receipt = db.get(EntityIndexReceipt, ids[0])
        assert receipt is not None and receipt.observation_count == 3
        rows = list(db.scalars(select(EntityObservation)))
        assert all(row.document_sha256 == snapshot.document_sha256 for row in rows)
    page = read(admin, f"/by-event/{ids[0]}")
    assert page["total"] == 3 and page["index_status"]["complete"]
    assert {row["kind"] for row in page["items"]} == {"host", "user", "process"}
    for row in page["items"]:
        detail = read(admin, f"/{row['id']}")
        assert detail["counts"]["events"] == detail["counts"]["observations"] == 1
        assert detail["risk"]["score"] is None and not detail["inventory_verified"]
        assert read(admin, f"/{row['id']}/events")["items"][0]["event_id"] == str(ids[0])
        assert read(admin, f"/{row['id']}/alerts")["total"] == 0
        assert read(admin, f"/{row['id']}/incidents")["total"] == 0
    assert counts(case) == before


def test_same_stable_identity_accepts_renamed_observed_labels(case: Case, admin: Login) -> None:
    normalize_inputs(
        case,
        admin,
        [
            auth_event(START, host={"id": "opaque", "name": "old"}),
            auth_event(START + timedelta(seconds=1), host={"id": "opaque", "name": "new"}),
        ],
    )
    page = read(admin, kind="host")
    assert page["total"] == 1
    host = page["items"][0]
    assert host["label"] == "new" and host["counts"]["events"] == 2
    assert host["first_seen"] == START.isoformat().replace("+00:00", "Z")
    with Session(case.database.runtime) as db:
        assert db.scalar(text("SELECT label FROM entity_identities WHERE kind='host'")) == "opaque"


def test_zero_entity_receipt_finishes_and_does_not_create_unknown(case: Case, admin: Login) -> None:
    _, ids = normalize_inputs(
        case,
        admin,
        [
            {
                "source_type": "generic_json",
                "timestamp": START.isoformat(),
                "raw_event": {"message": "plain"},
            }
        ],
    )
    assert read(admin)["items"] == []
    assert read(admin, f"/by-event/{ids[0]}")["index_status"]["complete"]
    assert backfill(admin)["events"] == 0
    with Session(case.database.runtime) as db:
        receipt = db.get(EntityIndexReceipt, ids[0])
        assert receipt is not None and receipt.observation_count == 0


def test_nonanchor_contributors_link_profile_and_time_window(case: Case, admin: Login) -> None:
    scope = uuid4(), uuid4()
    sequence = auth_sequence(START)
    # Preserve the correlation's source IP, and observe a destination IP only
    # in the earliest contributor, outside both alert anchors.
    sequence[0]["raw_event"]["destination"] = {"ip": "192.0.2.99"}
    _, ids = normalize_inputs(case, admin, sequence, replay=scope)
    seal(admin, scope, len(ids))
    correlate_once(processing_database(case), case.database.settings)
    record = next(row for row in alerts(case) if row.rule_id == "possible_bruteforce_compromise")
    assert record.event_id == ids[-1]
    params = {"mode": "replay", "dataset_id": str(scope[0]), "run_id": str(scope[1])}
    ip = next(
        row for row in read(admin, kind="ip", **params)["items"] if row["label"] == "192.0.2.99"
    )
    detail = read(admin, f"/{ip['id']}", **params)
    assert detail["counts"]["events"] == detail["counts"]["failed_logins"] == 1
    assert detail["counts"]["alerts"] == 2 and detail["risk"]["score"] == record.risk_score
    related = read(admin, f"/{ip['id']}/alerts", **params)
    assert related["total"] == 2
    sequence_alert = next(row for row in related["items"] if row["id"] == str(record.id))
    assert sequence_alert["contributing_event_count"] == 6
    assert sequence_alert["matched_entity_event_count"] == 1
    cutoff = {**params, "to": (START + timedelta(seconds=1)).isoformat()}
    first_only = read(admin, f"/{ip['id']}", **cutoff)
    assert first_only["counts"]["events"] == 1 and first_only["counts"]["alerts"] == 2
    assert read(admin)["total"] == 0
    assert (
        admin.client.get(
            f"/api/v1/entities/{ip['id']}", params=WINDOW, headers=admin.authorization
        ).status_code
        == 404
    )


def test_maximum_risk_excludes_false_positive_and_active_case_links_only(
    case: Case, admin: Login
) -> None:
    publish(admin, import_rule(admin, definition(level="critical")))
    normalize_inputs(case, admin, [powershell(), powershell("powershell -c get-date")])
    detect_once(processing_database(case), case.database.settings)
    records = alerts(case)
    assert len(records) == 2
    assert len({row.risk_score for row in records}) == 2
    user = read(admin, kind="user")["items"][0]
    path = f"/{user['id']}"
    before = read(admin, path)
    assert before["counts"]["alerts"] == before["counts"]["incidents"] == 2
    assert before["risk"]["score"] == max(row.risk_score for row in records)
    assert before["mitre"]["techniques"][0]["id"] == "T1059.001"
    assert before["mitre"]["techniques"][0]["alert_count"] == 2
    assert not before["risk"]["entity_calculation"]
    with Session(case.database.runtime) as db:
        calculations_before = db.scalar(text("SELECT count(*) FROM risk_calculations"))
    for record in records:
        response = admin.client.patch(
            f"/api/v1/alerts/{record.id}",
            json={"status": "false_positive"},
            headers={**admin.authorization, "If-Match": '"1"'},
        )
        assert response.status_code == 200, response.text
    after = read(admin, path)
    assert after["counts"]["alerts"] == after["counts"]["false_positive_alerts"] == 2
    assert after["counts"]["eligible_alerts"] == 0 and after["risk"]["score"] is None
    assert (
        after["mitre"]["techniques"] == [] and after["mitre"]["excluded_false_positive_alerts"] == 2
    )
    assert all(item["risk_score"] is None for item in read(admin, path + "/alerts")["items"])
    cases = read(admin, path + "/incidents")["items"]
    assert len(cases) == 2
    for item in cases:
        incident = admin.client.get(
            f"/api/v1/incidents/{item['id']}", headers=admin.authorization
        ).json()
        alert_id = incident["alerts"][0]["alert_id"] if "alerts" in incident else None
        if alert_id is None:
            with Session(case.database.runtime) as db:
                alert_id = str(
                    db.scalar(
                        text(
                            "SELECT alert_id FROM incident_alerts WHERE incident_id=:id AND active"
                        ),
                        {"id": UUID(item["id"])},
                    )
                )
        result = admin.client.delete(
            f"/api/v1/incidents/{item['id']}/alerts/{alert_id}",
            headers={**admin.authorization, "If-Match": f'"{incident["version"]}"'},
        )
        assert result.status_code == 200, result.text
    assert read(admin, path)["counts"]["incidents"] == 0
    assert read(admin, path + "/incidents")["total"] == 0
    assert calculations_before == 4


def test_sigma_profile_uses_frozen_existing_assessment(case: Case, admin: Login) -> None:
    rule = publish(admin, import_rule(admin, definition(level="critical")))
    normalize_events(case, admin, [powershell("powershell -c get-date")])
    detect_once(processing_database(case), case.database.settings)
    record = alerts(case)[0]
    assert record.rule_id == f"sigma:{rule['id']}"
    host = read(admin, kind="host")["items"][0]
    detail = read(admin, f"/{host['id']}")
    assert detail["risk"]["score"] == record.risk_score
    assert detail["risk"]["calculation_id"] == str(record.risk_calculation_id)
    assert detail["risk"]["policy_version"] == "risk-policy-v3"
    assert detail["mitre"]["techniques"][0]["id"] == "T1059.001"


def test_related_hosts_failed_login_counts_and_literal_search(case: Case, admin: Login) -> None:
    sid = "S-1-5-21-1-2-3-500"
    events = [
        auth_event(
            START + timedelta(seconds=i),
            host={"id": f"host{i}", "name": f"host_%{i}"},
            user={"id": sid, "name": "Administrator", "realm": "LAB"},
        )
        for i in range(3)
    ]
    for event in events:
        event["raw_event"]["host"]["os"] = "windows"
    normalize_inputs(case, admin, events)
    user = read(admin, kind="user")["items"][0]
    profile = read(admin, f"/{user['id']}")
    assert profile["counts"]["failed_logins"] == profile["related_host_count"] == 3
    related = read(admin, f"/{user['id']}/related", limit=1)
    assert related["total"] == 3 and len(related["items"]) == 1 and related["next_cursor"]
    assert read(admin, q="_%", kind="host")["total"] == 3
    assert read(admin, q="not-present' OR 1=1 --")["total"] == 0


def test_existing_v2_profile_priority_is_projected_without_recalculation(
    case: Case,
    admin: Login,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    record = alerts(case)[0]
    # Historical builtin proof has unchanged baseline, but its original input
    # shape omits the Sigma severity-baselines field introduced with policy v3.
    with Session(case.database.owner) as db:
        row = db.get(RiskCalculation, record.risk_calculation_id)
        assert row is not None
        snapshot = deepcopy(row.input_snapshot)
        snapshot["scoring_input"].pop("severity_baselines")
        row.policy_version = "risk-policy-v2"
        row.policy_hash = "fe87d0dd228f33d01ce32434cd8ac6620f4cf1d3723ebd077ca2add7b466e85c"
        row.input_snapshot = snapshot
        row.input_sha256 = hashlib.sha256(canonical_json(snapshot)).hexdigest()
        db.commit()

    def forbidden_calculation(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("GET must not recalculate historical risk")

    monkeypatch.setattr("app.modules.risk.engine.calculate", forbidden_calculation)
    host = read(admin, kind="host")["items"][0]
    first = read(admin, f"/{host['id']}")
    second = read(admin, f"/{host['id']}")
    assert first == second
    assert first["risk"]["policy_version"] == "risk-policy-v2"
    assert first["risk"]["score"] == 45
    assert first["risk"]["calculation_id"] == str(record.risk_calculation_id)
    with Session(case.database.runtime) as db:
        assert db.scalar(text("SELECT count(*) FROM risk_calculations")) == 2


def test_profile_and_activity_pagination_have_exact_totals(case: Case, admin: Login) -> None:
    normalize_inputs(case, admin, [auth_event(START + timedelta(seconds=i)) for i in range(4)])
    page = read(admin, limit=1)
    assert page["total"] == 3 and page["next_cursor"]
    identifiers = [page["items"][0]["id"]]
    while page["next_cursor"]:
        page = read(admin, limit=1, cursor=page["next_cursor"])
        assert page["total"] == 3
        identifiers.append(page["items"][0]["id"])
    assert len(identifiers) == len(set(identifiers)) == 3
    host = read(admin, kind="host")["items"][0]
    activity = read(admin, f"/{host['id']}/events", limit=2)
    assert activity["total"] == 4 and len(activity["items"]) == 2
    next_page = read(admin, f"/{host['id']}/events", limit=2, cursor=activity["next_cursor"])
    assert next_page["total"] == 4 and next_page["next_cursor"] is None
    assert len({item["event_id"] for item in activity["items"] + next_page["items"]}) == 4


def test_explicit_backfill_is_bounded_idempotent_and_get_does_not_index(
    case: Case,
    admin: Login,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as patch:
        patch.setattr("app.modules.normalization.processing.index_event", lambda *_: None)
        patch.setattr("app.modules.detections.processing.index_alert", lambda *_: None)
        normalize_inputs(case, admin, [powershell(), powershell("powershell -enc QQ==")])
        detect_once(processing_database(case), case.database.settings)
    before = counts(case)
    assert before["entity_index_receipts"] == 0 and before["entity_alert_receipts"] == 0
    page = read(admin)
    assert page["total"] == 0 and page["index_status"] == {
        "pending_events": 2,
        "pending_alerts": 2,
        "complete": False,
    }
    assert counts(case) == before
    first = backfill(admin, 1)
    assert first["events"] == 1 and first["alerts"] <= 1
    assert first["index_status"]["pending_events"] == 1
    second = backfill(admin)
    assert second["events"] == 1 and second["index_status"]["complete"]
    final = counts(case)
    repeated = backfill(admin)
    assert repeated["events"] == repeated["alerts"] == repeated["observations"] == 0
    assert counts(case) == final
    assert read(admin)["index_status"]["complete"]
    with Session(case.database.runtime) as db:
        assert (
            db.scalar(text("SELECT count(*) FROM audit_logs WHERE action='entities.backfilled'"))
            == 3
        )


def test_pipeline_entity_failure_rolls_back_normalized_snapshot(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An inserted snapshot and its projections never commit partially if indexing fails.
    with monkeypatch.context() as patch:

        def reject(*_: Any) -> None:
            raise ValueError("simulated index failure")

        patch.setattr("app.modules.normalization.processing.index_event", reject)
        with pytest.raises(ValueError, match="simulated index failure"):
            normalize_events(case, admin, [powershell()])
    with Session(case.database.runtime) as db:
        assert db.scalar(text("SELECT count(*) FROM normalized_events")) == 0
        assert db.scalar(text("SELECT count(*) FROM entity_index_receipts")) == 0
        assert db.scalar(text("SELECT count(*) FROM raw_events")) == 1


def test_old_cursor_keeps_backfill_receipt_anchor_and_status_consistent(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Capture a page before adding a receipt for an older normalized event.
    normalize_inputs(case, admin, [auth_event(START)])
    with monkeypatch.context() as patch:
        patch.setattr("app.modules.normalization.processing.index_event", lambda *_: None)
        normalize_inputs(case, admin, [auth_event(START, host={"id": "other", "name": "other"})])
    first = read(admin, limit=1)
    assert first["total"] == 3 and first["index_status"]["pending_events"] == 1
    assert first["next_cursor"]
    backfill(admin)
    second = read(admin, limit=1, cursor=first["next_cursor"])
    assert second["total"] == 3 and second["index_status"]["pending_events"] == 1
    assert read(admin)["index_status"]["pending_events"] == 0


def test_incident_cursor_excludes_cases_created_after_its_anchor(case: Case, admin: Login) -> None:
    from .test_incidents import create

    normalize_inputs(case, admin, [powershell(), powershell("powershell -enc QQ==")])
    detect_once(processing_database(case), case.database.settings)
    host = read(admin, kind="host")["items"][0]
    path = f"/{host['id']}/incidents"
    first = read(admin, path, limit=1)
    assert first["total"] == 2 and first["next_cursor"]
    newly_created = create(admin, alert_ids=[str(alerts(case)[0].id)])
    second = read(admin, path, limit=1, cursor=first["next_cursor"])
    assert second["total"] == 2 and second["next_cursor"] is None
    assert newly_created["id"] not in [row["id"] for row in first["items"] + second["items"]]
    assert read(admin, path)["total"] == 3
