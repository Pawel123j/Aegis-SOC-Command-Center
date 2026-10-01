"""Real PostgreSQL normalization durability, fenced recovery and operator permissions.

Projection callbacks simulate acknowledgement and worker failures here. Separate
ClickHouse tests verify that repeated delivery is deduplicated by the search store.
"""

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.infrastructure.database import Database, utcnow
from app.modules.audit.models import AuditLog
from app.modules.ingestion.models import RawEvent
from app.modules.ingestion.processing import process_event
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization import processing as pipeline_processing
from app.modules.normalization.models import NormalizedEvent, PipelineJob
from app.modules.normalization.processing import (
    Claim,
    claim_one,
    enqueue_staged,
    process_once,
    run_claim,
)

from .helper_ingestion import Source, accept, enroll, envelope, processing_database, status
from .helpers import Case, Login

pytestmark = pytest.mark.integration


def stage(
    case: Case, admin: Login, *, source_type: str = "generic_json", raw: Any = None
) -> tuple[Database, Source, dict[str, Any], UUID]:
    source = enroll(admin, source_types=[source_type])
    payload = {
        **envelope("pipeline_event", raw=raw),
        "source_type": source_type,
        "timestamp": "2026-09-30T12:00:00+02:00",
    }
    receipt = accept(admin.client, source, payload)
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)
    assert process_event(database, case.database.settings, event_id, 1) == "staged"
    return database, source, receipt, event_id


def normalize_staged(case: Case, database: Database) -> Claim:
    assert enqueue_staged(database, 10) == 1
    claim = claim_one(database, case.database.settings)
    assert claim is not None and claim.stage == "normalizing"
    projected: list[dict[str, Any]] = []
    assert run_claim(database, case.database.settings, claim, projected.append) == "normalized"
    assert projected == []
    return claim


def snapshot(case: Case, event_id: UUID) -> dict[str, Any]:
    with Session(case.database.runtime) as session:
        stored = session.get(NormalizedEvent, event_id)
        assert stored is not None
        assert hashlib.sha256(canonical_json(stored.document)).hexdigest() == stored.document_sha256
        return deepcopy(stored.document)


def ready_again(case: Case, event_id: UUID, *, expire_lease: bool = False) -> None:
    with Session(case.database.owner) as session:
        job = session.get(PipelineJob, event_id)
        assert job is not None
        job.available_at = utcnow() - timedelta(seconds=10)
        if expire_lease:
            job.lease_until = utcnow() - timedelta(seconds=10)
        session.commit()


def pipeline_view(admin: Login, event_id: UUID) -> Any:
    response = admin.client.get(f"/api/v1/events/{event_id}/pipeline", headers=admin.authorization)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["etag"] == f'"{response.json()["version"]}"'
    return response


def test_staged_event_becomes_immutable_normalized_snapshot_then_projected(
    case: Case, admin: Login
) -> None:
    raw = {"message": "Zażółć gęślą jaźń", "event": {"outcome": "failure"}}
    database, source, receipt, event_id = stage(case, admin, raw=raw)
    initial = status(admin.client, source, receipt)
    assert initial["counts"]["staged"] == 1
    assert initial["counts"]["normalized"] == initial["counts"]["projected"] == 0
    assert initial["records"][0]["pipeline_state"] is None
    assert (
        admin.client.get(
            f"/api/v1/events/{event_id}/pipeline", headers=admin.authorization
        ).status_code
        == 404
    )

    normalize_staged(case, database)
    document = snapshot(case, event_id)
    with Session(case.database.runtime) as session:
        original = session.get(RawEvent, event_id)
        stored = session.get(NormalizedEvent, event_id)
        assert original is not None and stored is not None
        assert document["event_id"] == str(event_id)
        assert document["source_id"] == source.id
        assert document["dataset_id"] == str(original.dataset_id)
        assert document["run_id"] == str(original.run_id)
        assert document["mode"] == original.mode
        assert document["source_event_id"] == "pipeline_event"
        assert document["raw_event"] == raw
        assert document["raw_sha256"] == original.payload_hash
        assert stored.timestamp == datetime(2026, 9, 30, 10, tzinfo=UTC)
        assert stored.processed_at >= original.received_at
    normalized = status(admin.client, source, receipt)
    assert normalized["counts"]["normalized"] == 1
    assert normalized["counts"]["processed"] == normalized["counts"]["projected"] == 0
    assert normalized["records"][0]["pipeline_state"] == "normalized"

    claim = claim_one(database, case.database.settings)
    assert claim is not None and claim.stage == "projecting"
    delivered: list[dict[str, Any]] = []
    assert run_claim(database, case.database.settings, claim, delivered.append) == "projected"
    assert delivered == [document]
    projected = status(admin.client, source, receipt)
    assert projected["counts"]["staged"] == projected["counts"]["normalized"] == 1
    assert projected["counts"]["projected"] == 1
    assert projected["counts"]["processed"] == 0  # Detection is a separate later stage.
    assert projected["records"][0]["pipeline_state"] == "projected"
    assert enqueue_staged(database, 10) == 0
    assert claim_one(database, case.database.settings) is None
    assert process_once(database, case.database.settings, delivered.append) == {}
    assert len(delivered) == 1
    with Session(case.database.runtime) as session:
        assert session.scalar(select(func.count()).select_from(NormalizedEvent)) == 1


def test_concurrent_sweeps_and_claimers_create_only_one_active_job(
    case: Case, admin: Login
) -> None:
    database, _, _, event_id = stage(case, admin)
    with ThreadPoolExecutor(max_workers=2) as executor:
        sweeps = [executor.submit(enqueue_staged, database, 10) for _ in range(2)]
        assert sorted(future.result(timeout=15) for future in sweeps) == [0, 1]
        claims = [executor.submit(claim_one, database, case.database.settings) for _ in range(2)]
        claimed = [future.result(timeout=15) for future in claims]
    winner = [claim for claim in claimed if claim is not None]
    assert len(winner) == 1 and winner[0].event_id == event_id
    assert run_claim(database, case.database.settings, winner[0], lambda _: None) == "normalized"
    view = pipeline_view(admin, event_id).json()
    assert view["normalization_attempts"] == 1 and view["projection_attempts"] == 0


def test_unknown_source_format_is_quarantined_without_snapshot_or_raw_data_leak(
    case: Case, admin: Login
) -> None:
    private_raw = "unsupported auth record private:sensitive"
    database, source, receipt, event_id = stage(
        case, admin, source_type="linux_auth", raw=private_raw
    )
    assert enqueue_staged(database, 10) == 1
    claim = claim_one(database, case.database.settings)
    assert claim is not None
    projected: list[dict[str, Any]] = []
    assert run_claim(database, case.database.settings, claim, projected.append) == "quarantined"
    assert projected == [] and claim_one(database, case.database.settings) is None
    view = pipeline_view(admin, event_id)
    assert private_raw not in view.text and source.token not in view.text
    assert re.fullmatch(r"[a-z_]{1,64}", view.json()["error_code"])
    record = status(admin.client, source, receipt)["records"][0]
    assert record["state"] == "staged" and record["pipeline_state"] == "quarantined"
    assert record["pipeline_error_code"] == view.json()["error_code"]
    with Session(case.database.runtime) as session:
        assert session.get(NormalizedEvent, event_id) is None
        original = session.get(RawEvent, event_id)
        assert original is not None and original.envelope["raw_event"] == private_raw


def test_projection_outage_retains_snapshot_then_retries_without_normalizing_again(
    case: Case, admin: Login
) -> None:
    database, source, receipt, event_id = stage(case, admin)
    normalize_staged(case, database)
    before = snapshot(case, event_id)
    claim = claim_one(database, case.database.settings)
    assert claim is not None and claim.stage == "projecting"
    private_error = "http://private:secret@clickhouse.invalid"

    def unavailable(document: dict[str, Any]) -> None:
        assert document == before
        # The processor releases its read transaction before external I/O.
        assert pipeline_view(admin, event_id).json()["state"] == "projecting"
        raise ConnectionError(private_error)

    assert run_claim(database, case.database.settings, claim, unavailable) == "normalized"
    view = pipeline_view(admin, event_id)
    assert view.json()["error_code"] == "projection_unavailable"
    assert private_error not in view.text
    assert snapshot(case, event_id) == before
    assert status(admin.client, source, receipt)["counts"]["projected"] == 0
    assert claim_one(database, case.database.settings) is None  # Durable backoff.
    ready_again(case, event_id)
    retry = claim_one(database, case.database.settings)
    assert retry is not None and retry.stage == "projecting" and retry.attempt == 2
    delivered: list[dict[str, Any]] = []
    assert run_claim(database, case.database.settings, retry, delivered.append) == "projected"
    assert delivered == [before] and snapshot(case, event_id) == before
    assert pipeline_view(admin, event_id).json()["normalization_attempts"] == 1


def test_worker_exit_after_projection_insert_replays_identical_persisted_snapshot(
    case: Case, admin: Login
) -> None:
    database, _, _, event_id = stage(case, admin)
    normalize_staged(case, database)
    before = snapshot(case, event_id)
    claim = claim_one(database, case.database.settings)
    assert claim is not None and claim.stage == "projecting"
    delivered: list[dict[str, Any]] = []

    def insert_then_exit(document: dict[str, Any]) -> None:
        delivered.append(deepcopy(document))
        raise SystemExit("simulated exit after external acknowledgement")

    with pytest.raises(SystemExit):
        run_claim(database, case.database.settings, claim, insert_then_exit)
    interrupted = pipeline_view(admin, event_id).json()
    assert interrupted["state"] == "projecting" and interrupted["projection_attempts"] == 1
    assert claim_one(database, case.database.settings) is None
    ready_again(case, event_id, expire_lease=True)
    replacement = claim_one(database, case.database.settings)
    assert replacement is not None and replacement.token != claim.token
    assert run_claim(database, case.database.settings, replacement, delivered.append) == "projected"
    assert delivered == [before, before]
    assert snapshot(case, event_id) == before
    assert pipeline_view(admin, event_id).json()["normalization_attempts"] == 1


def test_expired_normalization_claim_cannot_commit_over_current_lease(
    case: Case, admin: Login
) -> None:
    database, _, _, event_id = stage(case, admin)
    assert enqueue_staged(database, 10) == 1
    old = claim_one(database, case.database.settings)
    assert old is not None
    ready_again(case, event_id, expire_lease=True)
    current = claim_one(database, case.database.settings)
    assert current is not None and current.token != old.token
    assert run_claim(database, case.database.settings, old, lambda _: None) == "stale"
    with Session(case.database.runtime) as session:
        assert session.get(NormalizedEvent, event_id) is None
    assert run_claim(database, case.database.settings, current, lambda _: None) == "normalized"
    view = pipeline_view(admin, event_id).json()
    assert view["state"] == "normalized" and view["normalization_attempts"] == 2
    with Session(case.database.runtime) as session:
        assert session.scalar(select(func.count()).select_from(NormalizedEvent)) == 1


def test_transient_parser_failure_is_redacted_and_recovers_after_persisted_backoff(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _, _, event_id = stage(case, admin)
    assert enqueue_staged(database, 10) == 1
    claim = claim_one(database, case.database.settings)
    assert claim is not None
    private_error = "private parser payload and credentials"

    def unavailable(*_: Any) -> Any:
        raise RuntimeError(private_error)

    with monkeypatch.context() as patch:
        patch.setattr(pipeline_processing, "normalize", unavailable)
        assert run_claim(database, case.database.settings, claim, lambda _: None) == "pending"
    view = pipeline_view(admin, event_id)
    assert view.json()["error_code"] == "normalization_failed"
    assert private_error not in view.text
    assert claim_one(database, case.database.settings) is None
    with Session(case.database.runtime) as session:
        assert session.get(NormalizedEvent, event_id) is None
    ready_again(case, event_id)
    replacement = claim_one(database, case.database.settings)
    assert replacement is not None and replacement.attempt == 2
    assert run_claim(database, case.database.settings, replacement, lambda _: None) == "normalized"
    assert pipeline_view(admin, event_id).json()["error_code"] is None


def test_snapshot_and_progress_commit_atomically_and_database_error_can_recover(
    case: Case, admin: Login
) -> None:
    database, _, _, event_id = stage(case, admin)
    assert enqueue_staged(database, 10) == 1
    claim = claim_one(database, case.database.settings)
    assert claim is not None
    with case.database.owner.begin() as connection:
        connection.execute(text("REVOKE INSERT ON normalized_events FROM aegis_app"))
    try:
        with pytest.raises(DBAPIError):
            run_claim(database, case.database.settings, claim, lambda _: None)
    finally:
        with case.database.owner.begin() as connection:
            connection.execute(text("GRANT INSERT ON normalized_events TO aegis_app"))
    assert pipeline_view(admin, event_id).json()["state"] == "normalizing"
    with Session(case.database.runtime) as session:
        assert session.get(NormalizedEvent, event_id) is None
    ready_again(case, event_id, expire_lease=True)
    replacement = claim_one(database, case.database.settings)
    assert replacement is not None
    assert run_claim(database, case.database.settings, replacement, lambda _: None) == "normalized"
    snapshot(case, event_id)


def test_repeated_parser_worker_crashes_have_bounded_attempts(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _, _, event_id = stage(case, admin)
    assert enqueue_staged(database, 10) == 1
    settings = case.database.settings.model_copy(update={"pipeline_max_normalization_attempts": 2})

    def crash(*_: Any) -> Any:
        raise SystemExit("simulated parser worker exit")

    with monkeypatch.context() as patch:
        patch.setattr(pipeline_processing, "normalize", crash)
        for attempt in (1, 2):
            claim = claim_one(database, settings)
            assert claim is not None and claim.attempt == attempt
            with pytest.raises(SystemExit):
                run_claim(database, settings, claim, lambda _: None)
            assert pipeline_view(admin, event_id).json()["state"] == "normalizing"
            ready_again(case, event_id, expire_lease=True)
    assert claim_one(database, settings) is None
    view = pipeline_view(admin, event_id).json()
    assert view["state"] == "quarantined" and view["normalization_attempts"] == 2
    assert view["error_code"] == "normalization_exhausted"
    with Session(case.database.runtime) as session:
        assert session.get(NormalizedEvent, event_id) is None


@pytest.mark.parametrize("late_failure", [False, True])
def test_late_projection_completion_cannot_overwrite_successful_reclaimer(
    case: Case, admin: Login, late_failure: bool
) -> None:
    database, _, _, event_id = stage(case, admin)
    normalize_staged(case, database)
    before = snapshot(case, event_id)
    old = claim_one(database, case.database.settings)
    assert old is not None and old.stage == "projecting"

    def reclaimed_while_in_flight(document: dict[str, Any]) -> None:
        assert document == before
        ready_again(case, event_id, expire_lease=True)
        current = claim_one(database, case.database.settings)
        assert current is not None and current.token != old.token
        assert run_claim(database, case.database.settings, current, lambda _: None) == "projected"
        if late_failure:
            raise ConnectionError("late private network error")

    assert run_claim(database, case.database.settings, old, reclaimed_while_in_flight) == "stale"
    view = pipeline_view(admin, event_id).json()
    assert view["state"] == "projected" and view["error_code"] is None
    assert view["projection_attempts"] == 2
    assert snapshot(case, event_id) == before


def test_projection_budget_is_bounded_and_admin_retry_preserves_snapshot(
    case: Case, admin: Login
) -> None:
    database, source, _, event_id = stage(case, admin)
    normalize_staged(case, database)
    before = snapshot(case, event_id)
    settings = case.database.settings.model_copy(update={"pipeline_max_projection_attempts": 2})

    def unavailable(_: dict[str, Any]) -> None:
        raise ConnectionError("private backend password")

    for expected in ("normalized", "projection_failed"):
        claim = claim_one(database, settings)
        assert claim is not None and claim.stage == "projecting"
        assert run_claim(database, settings, claim, unavailable) == expected
        ready_again(case, event_id)
    assert claim_one(database, settings) is None
    failed = pipeline_view(admin, event_id)
    assert failed.json()["state"] == "projection_failed"
    assert failed.json()["projection_attempts"] == 2
    path = f"/api/v1/events/{event_id}/pipeline/retry"
    match = failed.headers["etag"]
    assert admin.client.post(path, headers=admin.authorization).status_code == 428
    assert (
        admin.client.post(path, headers={**source.authorization, "If-Match": match}).status_code
        == 401
    )
    manager_user = case.create_user(admin, "soc_manager")
    manager = case.login(str(manager_user["username"]), str(manager_user["password"]))
    assert (
        manager.client.post(path, headers={**manager.authorization, "If-Match": match}).status_code
        == 403
    )
    assert (
        admin.client.post(path, headers={**admin.authorization, "If-Match": '"0"'}).status_code
        == 412
    )
    retried = admin.client.post(path, headers={**admin.authorization, "If-Match": match})
    assert retried.status_code == 200 and retried.json()["state"] == "normalized"
    assert retried.headers["etag"] != match
    assert retried.json()["projection_attempts"] == 0
    assert retried.json()["normalization_attempts"] == 1
    assert snapshot(case, event_id) == before
    assert (
        admin.client.post(path, headers={**admin.authorization, "If-Match": match}).status_code
        == 412
    )
    assert (
        admin.client.post(
            path, headers={**admin.authorization, "If-Match": retried.headers["etag"]}
        ).status_code
        == 409
    )
    with Session(case.database.runtime) as session:
        audit = session.scalar(select(AuditLog).where(AuditLog.action == "events.pipeline_retried"))
        assert audit is not None and audit.actor_id == UUID(admin.user_id)
        assert audit.object_id == str(event_id)
        assert audit.details == {"previous_state": "projection_failed"}
        assert audit.request_id == retried.headers["x-request-id"]
    claim = claim_one(database, settings)
    assert claim is not None and claim.attempt == 1
    assert run_claim(database, settings, claim, lambda _: None) == "projected"


def test_normalization_quarantine_retry_is_versioned_and_does_not_rewrite_raw(
    case: Case, admin: Login
) -> None:
    private_raw = "unsupported linux auth entry"
    database, _, _, event_id = stage(case, admin, source_type="linux_auth", raw=private_raw)
    assert enqueue_staged(database, 10) == 1
    claim = claim_one(database, case.database.settings)
    assert claim is not None
    assert run_claim(database, case.database.settings, claim, lambda _: None) == "quarantined"
    failed = pipeline_view(admin, event_id)
    retried = admin.client.post(
        f"/api/v1/events/{event_id}/pipeline/retry",
        headers={**admin.authorization, "If-Match": failed.headers["etag"]},
    )
    assert retried.status_code == 200 and retried.json()["state"] == "pending"
    assert retried.json()["normalization_attempts"] == 0
    assert retried.json()["error_code"] is None
    assert retried.json()["version"] > failed.json()["version"]
    replacement = claim_one(database, case.database.settings)
    assert replacement is not None and replacement.token != claim.token
    assert run_claim(database, case.database.settings, replacement, lambda _: None) == "quarantined"
    assert run_claim(database, case.database.settings, claim, lambda _: None) == "stale"
    with Session(case.database.runtime) as session:
        raw = session.get(RawEvent, event_id)
        assert raw is not None and raw.envelope["raw_event"] == private_raw
        assert session.get(NormalizedEvent, event_id) is None


def test_retry_and_audit_rollback_together_if_audit_storage_rejects_insert(
    case: Case, admin: Login
) -> None:
    database, _, _, event_id = stage(case, admin, source_type="linux_auth", raw="unsupported")
    assert enqueue_staged(database, 10) == 1
    claim = claim_one(database, case.database.settings)
    assert claim is not None
    assert run_claim(database, case.database.settings, claim, lambda _: None) == "quarantined"
    failed = pipeline_view(admin, event_id)
    with case.database.owner.begin() as connection:
        connection.execute(text("REVOKE INSERT ON audit_logs FROM aegis_app"))
    try:
        rejected = admin.client.post(
            f"/api/v1/events/{event_id}/pipeline/retry",
            headers={**admin.authorization, "If-Match": failed.headers["etag"]},
        )
        assert rejected.status_code == 503
    finally:
        with case.database.owner.begin() as connection:
            connection.execute(text("GRANT INSERT ON audit_logs TO aegis_app"))
    assert pipeline_view(admin, event_id).json() == failed.json()
    with Session(case.database.runtime) as session:
        assert (
            session.scalar(select(AuditLog.id).where(AuditLog.action == "events.pipeline_retried"))
            is None
        )


def test_pipeline_read_permissions_and_system_backlog_come_from_persisted_state(
    case: Case, admin: Login
) -> None:
    database, source, _, event_id = stage(case, admin)
    assert enqueue_staged(database, 10) == 1
    path = f"/api/v1/events/{event_id}/pipeline"
    assert admin.client.get(path, headers=source.authorization).status_code == 401
    assert admin.client.get(path).status_code == 401
    read_only_user = case.create_user(admin, "read_only")
    reader = case.login(str(read_only_user["username"]), str(read_only_user["password"]))
    assert reader.client.get(path, headers=reader.authorization).status_code == 200
    assert (
        reader.client.get("/api/v1/system/pipeline", headers=reader.authorization).status_code
        == 403
    )
    view = admin.client.get("/api/v1/system/pipeline", headers=admin.authorization)
    assert view.status_code == 200 and view.headers["cache-control"] == "no-store"
    assert view.json()["states"] == {"pending": 1}
    assert view.json()["oldest_pending_seconds"] >= 0
    assert (
        admin.client.get(
            f"/api/v1/events/{uuid4()}/pipeline", headers=admin.authorization
        ).status_code
        == 404
    )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE normalized_events SET document_sha256 = repeat('0', 64)",
        "DELETE FROM normalized_events",
        "TRUNCATE normalized_events",
        "DELETE FROM pipeline_jobs",
        "ALTER TABLE normalized_events ADD COLUMN tampered text",
        "DROP TABLE pipeline_jobs",
    ],
)
def test_runtime_cannot_rewrite_normalized_evidence_or_delete_durable_jobs(
    case: Case, admin: Login, statement: str
) -> None:
    database, _, _, event_id = stage(case, admin)
    normalize_staged(case, database)
    before = snapshot(case, event_id)
    with case.database.runtime.connect() as connection:
        with pytest.raises(DBAPIError) as rejected:
            connection.execute(text(statement))
        assert getattr(rejected.value.orig, "sqlstate", None) == "42501"
    assert snapshot(case, event_id) == before


def test_projection_verifies_snapshot_integrity_before_external_write(
    case: Case, admin: Login
) -> None:
    database, _, _, event_id = stage(case, admin)
    normalize_staged(case, database)
    # A database owner can change evidence; a runtime role cannot. The checksum
    # detects an accidental owner-side document change before projecting it.
    with Session(case.database.owner) as session:
        stored = session.get(NormalizedEvent, event_id)
        assert stored is not None
        stored.document = {**stored.document, "raw_event": {"tampered": True}}
        session.commit()
    claim = claim_one(database, case.database.settings)
    assert claim is not None and claim.stage == "projecting"
    delivered: list[dict[str, Any]] = []
    assert (
        run_claim(database, case.database.settings, claim, delivered.append) == "projection_failed"
    )
    assert delivered == []
    assert pipeline_view(admin, event_id).json()["error_code"] == "integrity_mismatch"
