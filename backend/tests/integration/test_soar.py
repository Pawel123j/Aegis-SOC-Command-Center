"""Real PostgreSQL workflows, authorization, fencing, rollback and crash recovery."""

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.modules.detections.processing import process_once as detect_once
from app.modules.incidents.models import Incident
from app.modules.intelligence.models import IOCIdentity
from app.modules.soar import processing
from app.modules.soar.models import (
    PlaybookAttempt,
    PlaybookEffect,
    PlaybookRun,
    PlaybookStep,
    SoarNotification,
)
from app.modules.soar.schemas import ACTION_LABELS
from app.modules.users.models import User

from .helper_correlation import auth_event, normalize_inputs
from .helper_ingestion import processing_database
from .helpers import Case, Login, migrate
from .test_initial_alerts import alerts, user
from .test_intelligence_pipeline import ioc, patch

pytestmark = pytest.mark.integration


def book(admin: Login, actions: list[str] | None = None, *, publish: bool = True) -> dict[str, Any]:
    response = admin.client.post(
        "/api/v1/playbooks",
        headers=admin.authorization,
        json={
            "title": "Local response",
            "steps": [
                {"id": f"step_{i}", "action": value}
                for i, value in enumerate(actions or list(ACTION_LABELS))
            ],
        },
    )
    assert response.status_code == 201, response.text
    result = response.json()
    if publish:
        response = admin.client.post(
            f"/api/v1/playbooks/{result['id']}/publish",
            json={"revision": 1},
            headers={**admin.authorization, "If-Match": response.headers["etag"]},
        )
        assert response.status_code == 200, response.text
        result = response.json()
    return dict(result)


def source_alert(case: Case, admin: Login, *, replay: tuple[UUID, UUID] | None = None) -> Any:
    ioc(admin)
    normalize_inputs(
        case,
        admin,
        [auth_event(datetime(2026, 10, 1, tzinfo=UTC), destination={"ip": "198.51.100.19"})],
        replay=replay,
    )
    detect_once(processing_database(case), case.database.settings)
    return alerts(case)[0]


def start(
    admin: Login, definition: dict[str, Any], alert_id: UUID, *, key: str | None = None, **data: Any
) -> Any:
    return admin.client.post(
        f"/api/v1/playbooks/{definition['id']}/runs",
        json={"revision": definition["published_revision"], "alert_id": str(alert_id), **data},
        headers={**admin.authorization, "Idempotency-Key": key or uuid4().hex},
    )


def detail(admin: Login, identifier: str) -> dict[str, Any]:
    result = admin.client.get(f"/api/v1/playbook-runs/{identifier}", headers=admin.authorization)
    assert result.status_code == 200, result.text
    assert result.headers["cache-control"] == "no-store"
    return dict(result.json())


def drain(case: Case, count: int = 20) -> None:
    database = processing_database(case)
    for _ in range(count):
        processing.process_once(database)


def expire(case: Case, identity: str) -> None:
    with case.database.owner.begin() as db:
        now = datetime.now(UTC) - timedelta(seconds=1)
        db.execute(
            update(PlaybookRun).where(PlaybookRun.id == UUID(identity)).values(next_attempt_at=now)
        )
        db.execute(
            update(PlaybookStep)
            .where(PlaybookStep.run_id == UUID(identity), PlaybookStep.state == "running")
            .values(lease_until=now)
        )


def test_full_real_pipeline_procedure_preserves_proof_and_deduplicates(
    case: Case, admin: Login
) -> None:
    alert = source_alert(case, admin)
    definition = book(admin)
    key = uuid4().hex
    first = start(admin, definition, alert.id, key=key)
    assert first.status_code == 201, first.text
    identity = first.json()["id"]
    assert first.json()["state"] == "queued"
    drain(case)
    result = detail(admin, identity)
    assert result["state"] == "completed" and len(result["steps"]) == 9
    assert all(
        step["attempts"] == 1 and step["history"][0]["outcome"] == "completed"
        for step in result["steps"]
    )
    outputs = {step["action"]: step["output"] for step in result["steps"]}
    assert outputs["check_threat_intelligence"]["proof"]["match_count"] == 1
    assert outputs["calculate_risk"]["risk"]["score"] == alert.risk_score
    assert outputs["create_incident"]["created"] is True
    assert outputs["add_ioc"]["created"] is False
    assert all(outputs[a]["simulated"] for a in ACTION_LABELS if a.startswith("simulate_"))
    repeated = start(admin, definition, alert.id, key=key)
    assert repeated.status_code == 200 and repeated.json() == result
    assert start(admin, definition, alert.id, key=key, ip_field="destination").status_code == 409
    drain(case)
    with Session(case.database.runtime) as db:
        assert db.scalar(select(func.count()).select_from(Incident)) == 1
        assert db.scalar(select(func.count()).select_from(SoarNotification)) == 1
        assert db.scalar(select(func.count()).select_from(PlaybookEffect)) == 9
        assert db.scalar(select(func.count()).select_from(PlaybookAttempt)) == 9
    assert detail(admin, identity) == result


def test_revisions_are_pinned_and_edits_do_not_change_existing_runs(
    case: Case, admin: Login
) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst"])
    first = start(admin, definition, alert.id).json()
    revised = admin.client.post(
        f"/api/v1/playbooks/{definition['id']}/versions",
        json={
            "title": "Different version",
            "steps": [{"id": "other", "action": "simulate_webhook"}],
        },
        headers={**admin.authorization, "If-Match": f'"{definition["version"]}"'},
    )
    assert revised.status_code == 201, revised.text
    assert revised.json()["published_revision"] == 1
    drain(case)
    result = detail(admin, first["id"])
    assert result["revision"] == 1 and result["definition"]["title"] == "Local response"
    assert result["steps"][0]["action"] == "notify_analyst"
    stale = admin.client.post(
        f"/api/v1/playbooks/{definition['id']}/publish",
        json={"revision": 2},
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert stale.status_code == 412


@pytest.mark.parametrize(
    "change", ["disabled", "actor_disabled", "permission_revoked", "false_positive"]
)
def test_authority_and_playbook_rechecked_after_claim(
    case: Case, admin: Login, change: str
) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst"])
    analyst = user(case, admin, "soc_analyst")
    response = start(analyst, definition, alert.id)
    assert response.status_code == 201, response.text
    claim = processing.claim_next(processing_database(case))
    assert claim
    if change == "disabled":
        response = admin.client.patch(
            f"/api/v1/playbooks/{definition['id']}",
            json={"enabled": False},
            headers={**admin.authorization, "If-Match": f'"{definition["version"]}"'},
        )
        assert response.status_code == 200
    elif change == "false_positive":
        response = admin.client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": "false_positive"},
            headers={**admin.authorization, "If-Match": f'"{alert.version}"'},
        )
        assert response.status_code == 200, response.text
    else:
        with case.database.owner.begin() as db:
            db.execute(
                update(User)
                .where(User.id == UUID(analyst.user_id))
                .values(
                    **({"enabled": False} if change == "actor_disabled" else {"role": "read_only"})
                )
            )
    assert not processing.execute_claim(processing_database(case), claim)
    result = detail(admin, str(claim.run_id))
    assert result["state"] == "failed" and result["steps"][0]["output"] is None


@pytest.mark.parametrize("role", ["read_only", "soc_analyst"])
def test_readers_cannot_publish_and_viewer_cannot_run(case: Case, admin: Login, role: str) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst"])
    actor = user(case, admin, role)
    result = actor.client.post(
        "/api/v1/playbooks",
        json={"title": "Denied", "steps": [{"id": "one", "action": "notify_analyst"}]},
        headers=actor.authorization,
    )
    assert result.status_code == 403
    result = start(actor, definition, alert.id)
    assert result.status_code == (403 if role == "read_only" else 201)
    ioc_definition = book(admin, ["add_ioc"])
    assert start(actor, ioc_definition, alert.id).status_code == 403


@pytest.mark.parametrize("phase", ["queued", "claimed", "after_effect"])
def test_cancel_preserves_completed_effects_and_stops_next_step(
    case: Case, admin: Login, phase: str
) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst", "simulate_webhook"])
    row = start(admin, definition, alert.id).json()
    database = processing_database(case)
    claim = processing.claim_next(database) if phase == "claimed" else None
    if phase == "after_effect":
        assert processing.process_once(database)
    response = admin.client.post(
        f"/api/v1/playbook-runs/{row['id']}/cancel", json={}, headers=admin.authorization
    )
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "cancelled"
    if claim:
        assert not processing.execute_claim(database, claim)
    drain(case)
    result = detail(admin, row["id"])
    assert result["steps"][1]["not_executed_reason"] == "run_cancelled"
    with Session(case.database.runtime) as db:
        assert db.scalar(select(func.count()).select_from(SoarNotification)) == (
            1 if phase == "after_effect" else 0
        )
    repeated = admin.client.post(
        f"/api/v1/playbook-runs/{row['id']}/cancel", json={}, headers=admin.authorization
    )
    assert repeated.json() == result


def test_simultaneous_start_and_workers_commit_one_effect(case: Case, admin: Login) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["create_incident", "notify_analyst"])
    key = uuid4().hex
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: start(admin, definition, alert.id, key=key), range(2)))
    assert sorted(r.status_code for r in results) == [200, 201]
    assert results[0].json()["id"] == results[1].json()["id"]
    database = processing_database(case)
    for _ in range(4):
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda _: processing.process_once(database), range(2)))
    with Session(case.database.runtime) as db:
        assert db.scalar(select(func.count()).select_from(SoarNotification)) == 1
        assert db.scalar(select(func.count()).select_from(Incident)) == 1


def test_expired_worker_cannot_commit_after_new_fencing_token(case: Case, admin: Login) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst"])
    row = start(admin, definition, alert.id).json()
    database = processing_database(case)
    old = processing.claim_next(database)
    assert old and not processing.claim_next(database)
    expire(case, row["id"])
    new = processing.claim_next(database)
    assert new and new.token == 2
    assert not processing.execute_claim(database, old)
    assert processing.execute_claim(database, new)
    result = detail(admin, row["id"])
    assert [x["outcome"] for x in result["steps"][0]["history"]] == ["expired", "completed"]


@pytest.mark.parametrize("stage", ["before_effect", "before_commit", "after_commit"])
def test_killed_real_process_recovers_without_duplicate_local_effect(
    case: Case, admin: Login, stage: str
) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst"])
    row = start(admin, definition, alert.id).json()
    script = """
import os, signal
from app.core.config import get_settings
from app.infrastructure.database import Database
from app.modules.soar import processing
database = Database(get_settings())
original = processing.execute_action
stage = os.environ['AEGIS_TEST_CRASH_STAGE']
def crash(*args):
    if stage == 'before_effect': os.kill(os.getpid(), signal.SIGKILL)
    result = original(*args)
    args[0].flush()
    if stage == 'before_commit': os.kill(os.getpid(), signal.SIGKILL)
    return result
processing.execute_action = crash
assert processing.process_once(database)
os.kill(os.getpid(), signal.SIGKILL)
"""
    env = {
        **os.environ,
        "AEGIS_DATABASE_URL": case.database.settings.database_url.get_secret_value(),
        "AEGIS_TEST_CRASH_STAGE": stage,
    }
    child = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, timeout=15)
    assert child.returncode == -9, "Crash checkpoint was not reached (child output withheld)"
    if stage != "after_commit":
        expire(case, row["id"])
    drain(case)
    result = detail(admin, row["id"])
    assert result["state"] == "completed"
    assert result["steps"][0]["attempts"] == (1 if stage == "after_commit" else 2)
    with Session(case.database.runtime) as db:
        assert db.scalar(select(func.count()).select_from(SoarNotification)) == 1
        assert db.scalar(select(func.count()).select_from(PlaybookEffect)) == 1


def test_retry_budget_and_delay_are_durable(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst"])
    row = start(admin, definition, alert.id).json()

    def temporary(*args: Any) -> None:
        raise processing.TransientActionError()

    monkeypatch.setattr(processing, "execute_action", temporary)
    for number, delay in [(1, 5), (2, 20), (3, 0)]:
        assert not processing.process_once(processing_database(case))
        result = detail(admin, row["id"])
        assert result["steps"][0]["attempts"] == number
        if delay:
            finished = datetime.fromisoformat(result["steps"][0]["history"][-1]["finished_at"])
            next_try = datetime.fromisoformat(result["next_attempt_at"])
            assert (next_try - finished).total_seconds() == delay
            assert processing.claim_next(processing_database(case)) is None
            expire(case, row["id"])
    assert result["state"] == "failed"
    drain(case)
    assert detail(admin, row["id"]) == result


def test_three_crashed_attempts_are_terminal(case: Case, admin: Login) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst"])
    row = start(admin, definition, alert.id).json()
    for number in range(1, 4):
        claim = processing.claim_next(processing_database(case))
        assert claim and claim.token == number
        expire(case, row["id"])
    assert processing.claim_next(processing_database(case)) is None
    result = detail(admin, row["id"])
    assert result["state"] == "failed" and result["error_code"] == "soar_attempts_exhausted"
    assert len(result["steps"][0]["history"]) == 3


def test_ioc_catalog_snapshot_is_frozen_and_new_ip_is_inactive(case: Case, admin: Login) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["check_threat_intelligence", "add_ioc"])
    row = start(admin, definition, alert.id).json()
    current = admin.client.get("/api/v1/intelligence/iocs", headers=admin.authorization).json()[
        "items"
    ][0]
    patch(admin, current, reputation="clean", active=False)
    drain(case)
    result = detail(admin, row["id"])
    assert (
        result["steps"][0]["output"]["proof"]["matches"][0]["revision_snapshot"]["reputation"]
        == "malicious"
    )
    second = start(admin, definition, alert.id, ip_field="destination")
    assert second.status_code == 201, second.text
    drain(case)
    result = detail(admin, second.json()["id"])
    output = result["steps"][1]["output"]
    assert output["created"] and output["active"] is False and output["reputation"] == "unknown"
    item = admin.client.get(
        f"/api/v1/intelligence/iocs/{output['ioc_id']}", headers=admin.authorization
    ).json()
    assert item["value"] == "198.51.100.19" and not item["active"]


def test_replay_scope_never_mutates_global_ioc_catalog(case: Case, admin: Login) -> None:
    dataset, replay_id = uuid4(), uuid4()
    alert = source_alert(case, admin, replay=(dataset, replay_id))
    definition = book(admin, ["create_incident", "add_ioc", "notify_analyst"])
    row = start(admin, definition, alert.id, ip_field="destination").json()
    drain(case)
    result = detail(admin, row["id"])
    assert result["state"] == "completed" and result["steps"][1]["output"]["simulated"] is True
    with Session(case.database.runtime) as db:
        assert db.scalar(select(func.count()).select_from(IOCIdentity)) == 1
        incident = db.scalar(select(Incident))
        assert (
            incident
            and incident.mode == "replay"
            and incident.dataset_id == dataset
            and incident.run_id == replay_id
        )
    path = "/api/v1/playbook-runs"
    assert admin.client.get(path, headers=admin.authorization).json()["items"] == []
    assert admin.client.get(path + "?mode=replay", headers=admin.authorization).status_code == 422
    selected = admin.client.get(
        f"{path}?mode=replay&dataset_id={dataset}&data_run_id={replay_id}",
        headers=admin.authorization,
    )
    assert len(selected.json()["items"]) == 1


def test_local_inbox_is_private_and_read_idempotent(case: Case, admin: Login) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst"])
    analyst = user(case, admin, "soc_analyst")
    row = start(analyst, definition, alert.id).json()
    drain(case)
    own = analyst.client.get("/api/v1/soar-notifications", headers=analyst.authorization).json()[
        "items"
    ]
    assert len(own) == 1 and own[0]["run_id"] == row["id"]
    assert (
        admin.client.get("/api/v1/soar-notifications", headers=admin.authorization).json()["items"]
        == []
    )
    path = f"/api/v1/soar-notifications/{own[0]['id']}/read"
    assert admin.client.post(path, json={}, headers=admin.authorization).status_code == 404
    first = analyst.client.post(path, json={}, headers=analyst.authorization)
    assert first.status_code == 200 and first.json()["read_at"]
    assert analyst.client.post(path, json={}, headers=analyst.authorization).json() == first.json()


def test_failed_run_replay_is_new_history_with_explicit_notification(
    case: Case, admin: Login
) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst", "simulate_webhook"])
    row = start(admin, definition, alert.id).json()
    assert processing.process_once(processing_database(case))
    admin.client.post(
        f"/api/v1/playbook-runs/{row['id']}/cancel", json={}, headers=admin.authorization
    )
    prior = detail(admin, row["id"])
    second = start(admin, definition, alert.id, replay_of=row["id"])
    assert second.status_code == 201 and second.json()["id"] != row["id"]
    drain(case)
    assert detail(admin, row["id"]) == prior
    with Session(case.database.runtime) as db:
        messages = list(db.scalars(select(SoarNotification.message)))
        assert len(messages) == 2 and any(message.startswith("Powtórzenie") for message in messages)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE playbook_revisions SET document='{}'::jsonb",
        "DELETE FROM playbook_revisions",
        "UPDATE playbook_runs SET context='{}'::jsonb",
        "UPDATE playbook_steps SET action='shell'",
        "UPDATE playbook_attempts SET outcome='completed'",
        "DELETE FROM playbook_effects",
        "UPDATE soar_notifications SET recipient_id=gen_random_uuid()",
    ],
)
def test_runtime_cannot_rewrite_proof_or_history(case: Case, statement: str) -> None:
    with case.database.runtime.begin() as db, pytest.raises(DBAPIError) as denied:
        db.execute(text(statement))
    assert denied.value.orig.sqlstate == "42501"


def test_completed_history_cannot_be_requeued_or_downgraded(case: Case, admin: Login) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst"])
    row = start(admin, definition, alert.id).json()
    drain(case)
    with case.database.runtime.begin() as db, pytest.raises(DBAPIError) as denied:
        db.execute(
            update(PlaybookRun).where(PlaybookRun.id == UUID(row["id"])).values(state="queued")
        )
    assert denied.value.orig.sqlstate == "23514"
    with pytest.raises(DBAPIError):
        migrate(case.database.owner, "0011_intelligence", downgrade=True)
    assert detail(admin, row["id"])["state"] == "completed"


def test_audit_failure_rolls_back_local_action(case: Case, admin: Login) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst"])
    row = start(admin, definition, alert.id).json()
    claim = processing.claim_next(processing_database(case))
    assert claim
    with case.database.owner.begin() as db:
        db.execute(text("REVOKE INSERT ON audit_logs FROM aegis_app"))
    try:
        with pytest.raises(DBAPIError):
            processing.execute_claim(processing_database(case), claim)
    finally:
        with case.database.owner.begin() as db:
            db.execute(text("GRANT INSERT ON audit_logs TO aegis_app"))
    with Session(case.database.runtime) as db:
        assert db.scalar(select(func.count()).select_from(SoarNotification)) == 0
        assert db.scalar(select(func.count()).select_from(PlaybookEffect)) == 0
    expire(case, row["id"])
    drain(case)
    assert detail(admin, row["id"])["state"] == "completed"


@pytest.mark.parametrize(
    "data,code",
    [
        ({"execution_mode": "live"}, 422),
        ({"url": "http://127.0.0.1"}, 422),
        ({"ip": "169.254.169.254"}, 422),
        ({"revision": 20}, 409),
        ({"event_id": str(uuid4())}, 422),
        ({"replay_of": str(uuid4())}, 409),
    ],
)
def test_run_admission_rejects_unsafe_or_unrelated_inputs(
    case: Case, admin: Login, data: dict[str, Any], code: int
) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst"])
    response = start(admin, definition, alert.id, **data)
    assert response.status_code == code, response.text
    with Session(case.database.runtime) as db:
        assert db.scalar(select(func.count()).select_from(PlaybookRun)) == 0


def test_queue_capacity_deadline_and_unpublished_start_fail_closed(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.modules.soar import service

    alert = source_alert(case, admin)
    draft = book(admin, ["notify_analyst"], publish=False)
    assert start(admin, draft, alert.id, revision=1).status_code == 409
    definition = book(admin, ["notify_analyst"])
    monkeypatch.setattr(service, "MAX_ACTIVE_RUNS", 1)
    row = start(admin, definition, alert.id).json()
    assert start(admin, definition, alert.id).json()["code"] == "soar_queue_full"
    with case.database.owner.begin() as db:
        db.execute(
            update(PlaybookRun)
            .where(PlaybookRun.id == UUID(row["id"]))
            .values(deadline_at=datetime.now(UTC) - timedelta(seconds=1))
        )
    drain(case)
    result = detail(admin, row["id"])
    assert result["state"] == "failed" and result["error_code"] == "soar_deadline"
    assert (
        result["steps"][0]["attempts"] == 0
        and result["steps"][0]["not_executed_reason"] == "run_failed"
    )


def test_replay_cannot_switch_targets_or_reset_completed_history(case: Case, admin: Login) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst"])
    row = start(admin, definition, alert.id).json()
    admin.client.post(
        f"/api/v1/playbook-runs/{row['id']}/cancel", json={}, headers=admin.authorization
    )
    assert (
        start(admin, definition, alert.id, replay_of=row["id"], ip_field="destination").status_code
        == 409
    )
    new = start(admin, definition, alert.id, replay_of=row["id"]).json()
    drain(case)
    assert start(admin, definition, alert.id, replay_of=new["id"]).status_code == 409
    assert (
        admin.client.post(
            f"/api/v1/playbook-runs/{new['id']}/cancel", json={}, headers=admin.authorization
        ).status_code
        == 409
    )


def test_independent_runs_reuse_open_case_and_closed_case_requires_review(
    case: Case, admin: Login
) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["create_incident"])
    first = start(admin, definition, alert.id).json()
    drain(case)
    second = start(admin, definition, alert.id).json()
    drain(case)
    initial = detail(admin, first["id"])["steps"][0]["output"]
    repeated = detail(admin, second["id"])["steps"][0]["output"]
    assert repeated["incident_id"] == initial["incident_id"] and not repeated["created"]
    with case.database.owner.begin() as db:
        db.execute(
            update(Incident)
            .where(Incident.id == UUID(initial["incident_id"]))
            .values(status="closed")
        )
    third = start(admin, definition, alert.id).json()
    drain(case)
    failed = detail(admin, third["id"])
    assert failed["state"] == "failed" and failed["steps"][0]["attempts"] == 1
    assert failed["error_code"] == "soar_incident_review_required"


def test_oversized_output_rolls_back_effect_and_fails_permanently(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst"])
    row = start(admin, definition, alert.id).json()
    original = processing.execute_action

    def oversized(*args: Any) -> dict[str, Any]:
        result = original(*args)
        return {**result, "extra": "x" * 65536}

    monkeypatch.setattr(processing, "execute_action", oversized)
    drain(case)
    result = detail(admin, row["id"])
    assert result["error_code"] == "soar_output_limit" and result["steps"][0]["attempts"] == 1
    with Session(case.database.runtime) as db:
        assert db.scalar(select(func.count()).select_from(SoarNotification)) == 0


def test_run_history_pagination_has_scope_bound_cursor(case: Case, admin: Login) -> None:
    alert = source_alert(case, admin)
    definition = book(admin, ["notify_analyst"])
    identifiers = [start(admin, definition, alert.id).json()["id"] for _ in range(3)]
    first = admin.client.get("/api/v1/playbook-runs?limit=2", headers=admin.authorization).json()
    second = admin.client.get(
        f"/api/v1/playbook-runs?limit=2&before={first['next_cursor']}", headers=admin.authorization
    ).json()
    assert {row["id"] for row in first["items"] + second["items"]} == set(identifiers)
    assert len(first["items"]) == 2 and len(second["items"]) == 1 and second["next_cursor"] is None
    wrong = admin.client.get(
        f"/api/v1/playbook-runs?limit=2&before={first['next_cursor']}&alert_id={uuid4()}",
        headers=admin.authorization,
    )
    assert wrong.status_code == 422


def test_every_soar_route_requires_authentication(case: Case) -> None:
    client = case.client()
    for path in (
        "/playbooks",
        "/playbooks/actions",
        f"/playbooks/{uuid4()}",
        f"/playbook-targets/{uuid4()}",
        "/playbook-runs",
        f"/playbook-runs/{uuid4()}",
        "/soar-notifications",
    ):
        assert client.get("/api/v1" + path).status_code == 401
