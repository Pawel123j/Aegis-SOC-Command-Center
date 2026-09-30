"""Real PostgreSQL inbox/outbox guarantees across publication and worker failures."""

from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.modules.ingestion.models import OutboxJob, RawEvent
from app.modules.ingestion.processing import (
    EventSnapshot,
    PermanentProcessingError,
    TransientProcessingError,
    dispatch_once,
    process_event,
)

from .helper_ingestion import accept, due, enroll, envelope, processing_database, status
from .helpers import Case, Login

pytestmark = pytest.mark.integration


def test_poison_record_is_quarantined_without_blocking_healthy_record(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    receipt = accept(
        admin.client, source, {"events": [envelope("poison", raw=""), envelope("healthy")]}
    )
    records = status(admin.client, source, receipt)["records"]
    database = processing_database(case)
    states = [
        process_event(database, case.database.settings, UUID(row["event_id"]), 1) for row in records
    ]
    assert states == ["quarantined", "staged"]
    view = status(admin.client, source, receipt)
    assert view["counts"]["quarantined"] == view["counts"]["staged"] == 1
    assert all(view["counts"][key] == 0 for key in ("normalized", "processed", "projected"))
    assert view["records"][0]["error_code"] == "empty_payload"
    assert view["records"][1]["error_code"] is None


@pytest.mark.parametrize("raw", ["not JSON", "[]", "42"])
def test_generic_json_string_must_parse_to_object(case: Case, admin: Login, raw: str) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope(raw=raw))
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    assert (
        process_event(processing_database(case), case.database.settings, event_id, 1)
        == "quarantined"
    )
    assert status(admin.client, source, receipt)["records"][0]["error_code"] == "invalid_json"


def test_corrupted_raw_storage_is_quarantined_by_integrity_check(case: Case, admin: Login) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    with Session(case.database.owner) as session:
        raw = session.get(RawEvent, event_id)
        assert raw is not None
        raw.envelope = {**raw.envelope, "raw_event": {"tampered": True}}
        session.commit()
    assert (
        process_event(processing_database(case), case.database.settings, event_id, 1)
        == "quarantined"
    )
    record = status(admin.client, source, receipt)["records"][0]
    assert record["error_code"] == "integrity_mismatch"


def test_canonical_integrity_survives_postgresql_json_number_round_trip(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    receipt = accept(
        admin.client,
        source,
        envelope(raw={"huge": 1e100, "large": 1e20, "integral": 1.0, "fraction": 0.125}),
    )
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    assert process_event(processing_database(case), case.database.settings, event_id, 1) == "staged"


def test_duplicate_delivery_and_old_generation_do_not_reprocess(case: Case, admin: Login) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)
    assert process_event(database, case.database.settings, event_id, 1) == "staged"
    assert process_event(database, case.database.settings, event_id, 1) == "duplicate"
    assert process_event(database, case.database.settings, event_id, 0) == "stale"
    assert process_event(database, case.database.settings, uuid4(), 1) == "missing"
    record = status(admin.client, source, receipt)["records"][0]
    assert record["attempts"] == 1 and record["state"] == "staged"


def test_manual_retry_requires_admin_current_generation_and_quarantine(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope(raw=""))
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    path = f"/api/v1/events/{event_id}/retry"
    database = processing_database(case)
    assert (
        admin.client.post(path, headers={**admin.authorization, "If-Match": '"1"'}).status_code
        == 409
    )
    assert process_event(database, case.database.settings, event_id, 1) == "quarantined"
    assert admin.client.post(path, headers=admin.authorization).status_code == 428
    assert (
        admin.client.post(path, headers={**source.authorization, "If-Match": '"1"'}).status_code
        == 401
    )
    user = case.create_user(admin, "soc_manager")
    manager = case.login(str(user["username"]), str(user["password"]))
    assert (
        manager.client.post(path, headers={**manager.authorization, "If-Match": '"1"'}).status_code
        == 403
    )
    retried = admin.client.post(path, headers={**admin.authorization, "If-Match": '"1"'})
    assert retried.status_code == 200
    assert retried.json() == {"event_id": str(event_id), "state": "pending", "generation": 2}
    assert (
        admin.client.post(path, headers={**admin.authorization, "If-Match": '"1"'}).status_code
        == 412
    )
    assert process_event(database, case.database.settings, event_id, 1) == "stale"
    record = status(admin.client, source, receipt)["records"][0]
    assert record["generation"] == 2 and record["attempts"] == 0 and record["error_code"] is None
    # Retrying cannot repair or rewrite immutable source data.
    assert process_event(database, case.database.settings, event_id, 2) == "quarantined"
    with Session(case.database.runtime) as session:
        raw = session.get(RawEvent, event_id)
        assert raw is not None and raw.envelope["raw_event"] == ""


def test_manual_retry_obeys_pending_capacity_without_changing_generation(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    receipt = accept(
        admin.client, source, {"events": [envelope("poison", raw=""), envelope("pending")]}
    )
    records = status(admin.client, source, receipt)["records"]
    poison, pending = (UUID(record["event_id"]) for record in records)
    database = processing_database(case)
    assert process_event(database, case.database.settings, poison, 1) == "quarantined"
    client = case.client(case.database.settings.model_copy(update={"ingest_max_pending_events": 1}))
    path = f"/api/v1/events/{poison}/retry"
    headers = {**admin.authorization, "If-Match": '"1"'}
    rejected = client.post(path, headers=headers)
    assert rejected.status_code == 503
    assert rejected.json()["code"] == "ingest_backpressure"
    assert rejected.headers["retry-after"] == "5"
    unchanged = status(admin.client, source, receipt)["records"][0]
    assert unchanged["state"] == "quarantined" and unchanged["generation"] == 1
    assert process_event(database, case.database.settings, pending, 1) == "staged"
    admitted = client.post(path, headers=headers)
    assert admitted.status_code == 200 and admitted.json()["generation"] == 2


def test_retry_and_new_admission_cannot_overrun_pending_capacity(case: Case, admin: Login) -> None:
    from .helper_ingestion import submit

    source = enroll(admin)
    receipt = accept(admin.client, source, envelope("poison", raw=""))
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    assert (
        process_event(processing_database(case), case.database.settings, event_id, 1)
        == "quarantined"
    )
    settings = case.database.settings.model_copy(update={"ingest_max_pending_events": 1})
    retry_client, ingest_client = case.client(settings), case.client(settings)
    with ThreadPoolExecutor(max_workers=2) as executor:
        retry = executor.submit(
            retry_client.post,
            f"/api/v1/events/{event_id}/retry",
            headers={**admin.authorization, "If-Match": '"1"'},
        )
        ingest = executor.submit(submit, ingest_client, source, envelope("new"))
        codes = (retry.result(timeout=15).status_code, ingest.result(timeout=15).status_code)
    assert codes in ((200, 503), (503, 202))
    view = admin.client.get("/api/v1/system/ingestion", headers=admin.authorization).json()
    assert view["states"]["pending"] == 1 and view["states"]["processing"] == 0


def test_transient_failures_retry_then_quarantine_without_leaking_error_text(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)
    settings = case.database.settings.model_copy(update={"ingest_max_processing_attempts": 2})
    secret_error = "postgresql://private:credential@example.invalid/database"

    def failure(snapshot: EventSnapshot) -> None:
        raise RuntimeError(secret_error)

    assert process_event(database, settings, event_id, 1, processor=failure) == "pending"
    due(case, event_id)
    assert process_event(database, settings, event_id, 1, processor=failure) == "quarantined"
    view = status(admin.client, source, receipt)
    assert secret_error not in str(view)
    assert view["records"][0]["attempts"] == 2
    assert process_event(database, settings, event_id, 1) == "duplicate"


def test_transient_failure_recovers_on_later_attempt(case: Case, admin: Login) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)

    def failure(snapshot: EventSnapshot) -> None:
        raise TransientProcessingError()

    assert (
        process_event(database, case.database.settings, event_id, 1, processor=failure) == "pending"
    )
    due(case, event_id)
    assert process_event(database, case.database.settings, event_id, 1) == "staged"
    record = status(admin.client, source, receipt)["records"][0]
    assert record["attempts"] == 2 and record["error_code"] is None


def test_relay_retry_releases_processing_backoff_without_waiting_next_sweep(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)

    def transient(snapshot: EventSnapshot) -> None:
        raise TransientProcessingError()

    assert (
        process_event(database, case.database.settings, event_id, 1, processor=transient)
        == "pending"
    )
    assert process_event(database, case.database.settings, event_id, 1) == "busy"
    due(case, event_id)
    published: list[tuple[str, int]] = []
    assert (
        dispatch_once(
            database, case.database.settings, lambda *args: published.append(args)
        ).published
        == 1
    )
    assert published == [(str(event_id), 1)]
    # Relay scheduled its next sweep, but the actual processing backoff has elapsed.
    assert process_event(database, case.database.settings, event_id, 1) == "staged"
    assert status(admin.client, source, receipt)["records"][0]["attempts"] == 2


def test_active_worker_lease_prevents_simultaneous_processing(case: Case, admin: Login) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)

    def while_claimed(snapshot: EventSnapshot) -> None:
        assert process_event(database, case.database.settings, event_id, 1) == "busy"

    assert (
        process_event(database, case.database.settings, event_id, 1, processor=while_claimed)
        == "staged"
    )
    assert status(admin.client, source, receipt)["records"][0]["attempts"] == 1


def test_worker_crash_keeps_claim_and_expired_lease_can_be_reclaimed(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)

    def crash(snapshot: EventSnapshot) -> None:
        raise SystemExit("simulated worker exit")

    with pytest.raises(SystemExit):
        process_event(database, case.database.settings, event_id, 1, processor=crash)
    assert status(admin.client, source, receipt)["records"][0]["state"] == "processing"
    due(case, event_id, worker=True)
    assert process_event(database, case.database.settings, event_id, 1) == "staged"
    assert status(admin.client, source, receipt)["records"][0]["attempts"] == 2


def test_late_worker_failure_cannot_overwrite_successful_lease_reclaimer(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)

    def late_failure(snapshot: EventSnapshot) -> None:
        due(case, event_id, worker=True)
        assert process_event(database, case.database.settings, event_id, 1) == "staged"
        raise TransientProcessingError()

    assert (
        process_event(database, case.database.settings, event_id, 1, processor=late_failure)
        == "stale"
    )
    record = status(admin.client, source, receipt)["records"][0]
    assert record["state"] == "staged" and record["attempts"] == 2 and record["error_code"] is None


def test_old_worker_cannot_finish_after_manual_retry_starts_new_generation(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)

    def quarantine(snapshot: EventSnapshot) -> None:
        raise PermanentProcessingError("invalid_payload")

    def finish_late(snapshot: EventSnapshot) -> None:
        due(case, event_id, worker=True)
        assert (
            process_event(database, case.database.settings, event_id, 1, processor=quarantine)
            == "quarantined"
        )
        response = admin.client.post(
            f"/api/v1/events/{event_id}/retry",
            headers={**admin.authorization, "If-Match": '"1"'},
        )
        assert response.status_code == 200

    assert (
        process_event(database, case.database.settings, event_id, 1, processor=finish_late)
        == "stale"
    )
    record = status(admin.client, source, receipt)["records"][0]
    assert record["state"] == "pending" and record["generation"] == 2 and record["attempts"] == 0
    assert process_event(database, case.database.settings, event_id, 2) == "staged"


def test_concurrent_relays_claim_each_due_job_once(case: Case, admin: Login) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, {"events": [envelope(str(index)) for index in range(8)]})
    database = processing_database(case)
    settings = case.database.settings.model_copy(update={"ingest_dispatch_batch_size": 4})
    published: list[tuple[str, int]] = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(dispatch_once, database, settings, lambda *args: published.append(args))
            for _ in range(2)
        ]
        results = [future.result(timeout=15) for future in futures]
    assert sum(result.published for result in results) == 8
    assert len(set(published)) == 8
    assert {identifier for identifier, generation in published if generation == 1} == {
        record["event_id"] for record in status(admin.client, source, receipt)["records"]
    }


@pytest.mark.parametrize("published_before_crash", [False, True])
def test_relay_crash_republishes_after_expired_lease_and_duplicate_is_safe(
    case: Case, admin: Login, published_before_crash: bool
) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)
    published: list[tuple[str, int]] = []

    def crash(identifier: str, generation: int) -> None:
        if published_before_crash:
            published.append((identifier, generation))
        raise SystemExit("simulated relay exit")

    with pytest.raises(SystemExit):
        dispatch_once(database, case.database.settings, crash)
    with Session(case.database.runtime) as session:
        job = session.get(OutboxJob, event_id)
        assert job is not None and job.dispatch_token is not None and job.dispatch_attempts == 1
    assert (
        dispatch_once(
            database, case.database.settings, lambda *args: published.append(args)
        ).claimed
        == 0
    )
    due(case, event_id)
    recovered = dispatch_once(
        database, case.database.settings, lambda *args: published.append(args)
    )
    assert recovered.claimed == recovered.published == 1
    assert published == [(str(event_id), 1)] * (2 if published_before_crash else 1)
    results = [
        process_event(database, case.database.settings, UUID(identifier), generation)
        for identifier, generation in published
    ]
    assert results == (["staged", "duplicate"] if published_before_crash else ["staged"])
    assert status(admin.client, source, receipt)["records"][0]["attempts"] == 1


def test_late_relay_publish_failure_cannot_overwrite_completed_worker(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)

    def process_then_fail(identifier: str, generation: int) -> None:
        assert (
            process_event(database, case.database.settings, UUID(identifier), generation)
            == "staged"
        )
        raise ConnectionError("publication acknowledgement lost")

    dispatch_once(database, case.database.settings, process_then_fail)
    record = status(admin.client, source, receipt)["records"][0]
    assert record["state"] == "staged" and record["error_code"] is None
    due(case, event_id)
    assert dispatch_once(database, case.database.settings, lambda *_: None).claimed == 0


def test_lost_queue_message_is_published_again_until_worker_finishes(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)
    # First callback returns success while simulating subsequent queue loss.
    assert dispatch_once(database, case.database.settings, lambda *_: None).published == 1
    due(case, event_id)
    published: list[tuple[str, int]] = []
    assert (
        dispatch_once(
            database, case.database.settings, lambda *args: published.append(args)
        ).published
        == 1
    )
    assert published == [(str(event_id), 1)]
    assert process_event(database, case.database.settings, event_id, 1) == "staged"


def test_publish_failure_budget_quarantines_and_keeps_raw_payload(case: Case, admin: Login) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)
    settings = case.database.settings.model_copy(update={"ingest_max_dispatch_attempts": 2})

    def unavailable(identifier: str, generation: int) -> None:
        raise ConnectionError("private backend address")

    assert dispatch_once(database, settings, unavailable).failed == 1
    due(case, event_id)
    dispatch_once(database, settings, unavailable)
    record = status(admin.client, source, receipt)["records"][0]
    assert record["state"] == "quarantined" and record["error_code"] == "dispatch_exhausted"
    assert record["attempts"] == 0
    with Session(case.database.runtime) as session:
        assert session.get(RawEvent, event_id) is not None


def test_successful_but_unconsumed_publications_have_bounded_dispatch_budget(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    event_id = UUID(status(admin.client, source, receipt)["records"][0]["event_id"])
    database = processing_database(case)
    settings = case.database.settings.model_copy(update={"ingest_max_dispatch_attempts": 2})
    published: list[tuple[str, int]] = []
    for _ in range(2):
        assert (
            dispatch_once(database, settings, lambda *args: published.append(args)).published == 1
        )
        due(case, event_id)
    exhausted = dispatch_once(database, settings, lambda *args: published.append(args))
    assert exhausted.quarantined == 1 and exhausted.claimed == exhausted.published == 0
    assert published == [(str(event_id), 1), (str(event_id), 1)]
    record = status(admin.client, source, receipt)["records"][0]
    assert record["state"] == "quarantined" and record["error_code"] == "dispatch_exhausted"


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM ingest_capacity",
        "INSERT INTO ingest_capacity (id,event_count,byte_count) VALUES (2,0,0)",
        "DELETE FROM raw_events",
        "UPDATE raw_events SET payload_hash = repeat('0', 64)",
        "DELETE FROM ingestion_batches",
        "UPDATE ingestion_batches SET request_id = 'tampered'",
        "DELETE FROM batch_events",
        "UPDATE batch_events SET position = 0",
        "DELETE FROM outbox_jobs",
    ],
)
def test_runtime_cannot_delete_durable_ingestion_storage(case: Case, statement: str) -> None:
    with case.database.runtime.connect() as connection:
        with pytest.raises(DBAPIError) as rejected:
            connection.execute(text(statement))
        assert getattr(rejected.value.orig, "sqlstate", None) == "42501"
