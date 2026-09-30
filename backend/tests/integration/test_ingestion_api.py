"""Durable admission, source authorization and atomic rollback against PostgreSQL."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.core.security import random_token, token_hash
from app.infrastructure.database import utcnow
from app.modules.ingestion.models import IngestionSource, OutboxJob, RawEvent, SourceCredential

from .helper_ingestion import accept, enroll, envelope, status, stored_counts, submit
from .helpers import Case, Login

pytestmark = pytest.mark.integration


def test_ingest_persists_raw_membership_and_outbox_before_202(case: Case, admin: Login) -> None:
    source = enroll(admin)
    batch = accept(admin.client, source, {"events": [envelope("a"), envelope("b")]})
    assert (batch["accepted_count"], batch["created_count"], batch["duplicate_count"]) == (2, 2, 0)
    view = status(admin.client, source, batch)
    assert view["counts"] == {
        "pending": 2,
        "processing": 0,
        "staged": 0,
        "quarantined": 0,
        "normalized": 0,
        "processed": 0,
        "projected": 0,
    }
    assert [row["position"] for row in view["records"]] == [0, 1]
    assert all(row["generation"] == 1 and row["attempts"] == 0 for row in view["records"])
    with Session(case.database.runtime) as session:
        configured = session.get(IngestionSource, UUID(source.id))
        assert configured is not None
        rows = session.scalars(select(RawEvent)).all()
        assert len(rows) == 2
        assert all(row.dataset_id == configured.dataset_id for row in rows)
        assert all(row.mode == "live" and row.run_id.int == 0 for row in rows)
        assert all(row.request_id == batch["request_id"] for row in rows)
        assert {row.id for row in rows} == set(session.scalars(select(OutboxJob.event_id)))
    counts = stored_counts(case)
    assert counts["capacity_events"] == 2 and counts["capacity_bytes"] > 0


def test_idempotency_replays_original_receipt_and_conflict_is_atomic(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    key = uuid4().hex
    first = accept(admin.client, source, envelope("stable"), key)
    before = stored_counts(case)
    repeated = accept(admin.client, source, {"events": [envelope("stable")]}, key)
    assert repeated == first
    conflict = submit(admin.client, source, envelope("stable", raw={"changed": True}), key)
    assert conflict.status_code == 409
    assert stored_counts(case) == before


def test_source_event_deduplication_preserves_order_and_never_uses_content_only(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    batch = accept(
        admin.client,
        source,
        {"events": [envelope("same"), envelope("same"), envelope(), envelope()]},
    )
    assert (batch["accepted_count"], batch["created_count"], batch["duplicate_count"]) == (4, 3, 1)
    records = status(admin.client, source, batch)["records"]
    assert records[0]["event_id"] == records[1]["event_id"]
    assert len({record["event_id"] for record in records}) == 3
    repeat = accept(admin.client, source, envelope("same"))
    assert repeat["created_count"] == 0 and repeat["duplicate_count"] == 1
    assert stored_counts(case)["RawEvent"] == 3


@pytest.mark.parametrize("existing", [False, True])
def test_conflicting_source_id_rolls_back_entire_batch(
    case: Case, admin: Login, existing: bool
) -> None:
    source = enroll(admin)
    if existing:
        accept(admin.client, source, envelope("collision"))
    before = stored_counts(case)
    events = [envelope("new"), envelope("collision"), envelope("collision", raw={"other": 1})]
    response = submit(admin.client, source, {"events": events})
    assert response.status_code == 409
    assert stored_counts(case) == before


def test_same_keys_in_other_source_are_independent(case: Case, admin: Login) -> None:
    sources = [enroll(admin), enroll(admin)]
    receipts = [accept(admin.client, source, envelope("same"), "same-key") for source in sources]
    assert receipts[0]["batch_id"] != receipts[1]["batch_id"]
    assert stored_counts(case)["RawEvent"] == 2
    denied = admin.client.get(receipts[0]["status_url"], headers=sources[1].authorization)
    assert denied.status_code == 404
    assert (
        admin.client.get(receipts[0]["status_url"], headers=admin.authorization).status_code == 200
    )


def test_concurrent_identical_admissions_commit_one_batch(case: Case, admin: Login) -> None:
    source = enroll(admin)
    clients = [case.client(), case.client()]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(submit, client, source, envelope("once"), "concurrent")
            for client in clients
        ]
        responses = [future.result(timeout=15) for future in futures]
    assert all(response.status_code == 202 for response in responses)
    assert responses[0].json() == responses[1].json()
    counts = stored_counts(case)
    assert counts["IngestionBatch"] == counts["RawEvent"] == counts["OutboxJob"] == 1


def test_concurrent_admissions_cannot_overrun_capacity(case: Case, admin: Login) -> None:
    source = enroll(admin)
    settings = case.database.settings.model_copy(update={"ingest_max_stored_events": 1})
    clients = [case.client(settings), case.client(settings)]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(submit, client, source, envelope(f"event-{index}"))
            for index, client in enumerate(clients)
        ]
        responses = [future.result(timeout=15) for future in futures]
    assert sorted(response.status_code for response in responses) == [202, 503]
    counts = stored_counts(case)
    assert counts["RawEvent"] == counts["OutboxJob"] == counts["capacity_events"] == 1


def test_maximum_valid_batch_keeps_all_positions(case: Case, admin: Login) -> None:
    source = enroll(admin)
    receipt = accept(
        admin.client, source, {"events": [envelope(str(index)) for index in range(500)]}
    )
    assert receipt["accepted_count"] == receipt["created_count"] == 500
    records = status(admin.client, source, receipt)["records"]
    assert [record["position"] for record in records] == list(range(500))
    assert len({record["event_id"] for record in records}) == 500


@pytest.mark.parametrize("role", ["soc_manager", "soc_analyst", "read_only"])
def test_only_admin_enrolls_sources_but_all_read_roles_can_inspect_batch_status(
    case: Case, admin: Login, role: str
) -> None:
    source = enroll(admin)
    receipt = accept(admin.client, source, envelope())
    user = case.create_user(admin, role)
    principal = case.login(str(user["username"]), str(user["password"]))
    denied = principal.client.post(
        "/api/v1/sources",
        json={"name": "unauthorized", "source_types": ["generic_json"]},
        headers=principal.authorization,
    )
    assert denied.status_code == 403
    assert (
        principal.client.get(receipt["status_url"], headers=principal.authorization).status_code
        == 200
    )
    assert (
        principal.client.get("/api/v1/sources", headers=principal.authorization).status_code == 403
    )


def test_human_access_token_cannot_ingest_and_source_token_cannot_manage_sources(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    response = admin.client.post(
        "/api/v1/events",
        json=envelope(),
        headers={**admin.authorization, "Idempotency-Key": "human-token"},
    )
    assert response.status_code == 401
    assert admin.client.get("/api/v1/sources", headers=source.authorization).status_code == 401
    assert stored_counts(case)["RawEvent"] == 0


def test_credentials_are_hashed_once_and_scopes_are_enforced(case: Case, admin: Login) -> None:
    source = enroll(admin)
    first = accept(admin.client, source, envelope())
    for scope, can_write, can_status in (
        ("events:write", True, False),
        ("events:status", False, True),
    ):
        created = admin.client.post(
            f"/api/v1/sources/{source.id}/credentials",
            json={"scopes": [scope], "expires_in_days": 1},
            headers=admin.authorization,
        )
        assert created.status_code == 201
        credential = created.json()
        # Credential issuance returns the one-time credential directly.
        token = credential["token"]
        headers = {"Authorization": f"Bearer {token}"}
        response = admin.client.post(
            "/api/v1/events",
            json=envelope(),
            headers={**headers, "Idempotency-Key": uuid4().hex},
        )
        assert response.status_code == (202 if can_write else 403)
        response = admin.client.get(first["status_url"], headers=headers)
        assert response.status_code == (200 if can_status else 403)
    with Session(case.database.runtime) as session:
        stored = session.get(SourceCredential, UUID(source.credential_id))
        assert stored is not None and stored.secret_hash == token_hash(source.token)
        assert source.token not in str(stored.__dict__)
    for path in ("/api/v1/sources", f"/api/v1/sources/{source.id}", "/api/v1/audit"):
        response = admin.client.get(path, headers=admin.authorization)
        assert response.status_code == 200
        assert source.token not in response.text and "secret_hash" not in response.text


@pytest.mark.parametrize("change", ["revoke", "expire", "disable"])
def test_source_credential_changes_take_effect_immediately(
    case: Case, admin: Login, change: str
) -> None:
    source = enroll(admin)
    batch = accept(admin.client, source, envelope())
    if change == "revoke":
        response = admin.client.delete(
            f"/api/v1/sources/{source.id}/credentials/{source.credential_id}",
            headers=admin.authorization,
        )
        assert response.status_code == 204
    elif change == "expire":
        with Session(case.database.owner) as session:
            credential = session.get(SourceCredential, UUID(source.credential_id))
            assert credential is not None
            credential.created_at = utcnow() - timedelta(days=2)
            credential.expires_at = utcnow() - timedelta(seconds=1)
            session.commit()
    else:
        response = admin.client.patch(
            f"/api/v1/sources/{source.id}",
            json={"enabled": False},
            headers={**admin.authorization, "If-Match": '"1"'},
        )
        assert response.status_code == 200 and response.headers["etag"] == '"2"'
    assert submit(admin.client, source, envelope()).status_code == 401
    assert admin.client.get(batch["status_url"], headers=source.authorization).status_code == 401
    assert stored_counts(case)["RawEvent"] == 1


@pytest.mark.parametrize(
    "payload",
    [
        {"events": []},
        {"events": [envelope()] * 501},
        {"events": [envelope(), {"source_type": "generic_json"}]},
        {"source_type": "unknown", "raw_event": {}},
        {**envelope(), "dataset_id": str(uuid4())},
        {**envelope(), "mode": "replay"},
        {**envelope(), "timestamp": "2026-09-28T12:00:00"},
        {**envelope(), "timestamp": "1700000000"},
        {**envelope(), "timestamp": "2026-09-28"},
        {**envelope(), "timezone": "not/a/timezone"},
        envelope(raw="x" * 65537),
    ],
)
def test_invalid_envelope_rejects_whole_request(case: Case, admin: Login, payload: Any) -> None:
    source = enroll(admin)
    response = submit(admin.client, source, payload)
    assert response.status_code == 422
    assert stored_counts(case)["RawEvent"] == stored_counts(case)["IngestionBatch"] == 0


def test_source_type_allowlist_is_enforced_atomically(case: Case, admin: Login) -> None:
    source = enroll(admin)
    response = submit(
        admin.client, source, {"events": [envelope(), {"source_type": "nginx", "raw_event": "ok"}]}
    )
    assert response.status_code == 422
    assert response.json()["code"] == "source_type_not_allowed"
    assert stored_counts(case)["RawEvent"] == 0


def test_missing_and_invalid_idempotency_keys_are_rejected(case: Case, admin: Login) -> None:
    source = enroll(admin)
    for key in (None, "bad key", "a" * 129):
        headers = source.authorization
        if key is not None:
            headers["Idempotency-Key"] = key
        response = admin.client.post("/api/v1/events", json=envelope(), headers=headers)
        assert response.status_code in (400, 422)
    assert stored_counts(case)["RawEvent"] == 0


def test_failed_audit_rolls_back_inbox_outbox_and_capacity(case: Case, admin: Login) -> None:
    source = enroll(admin)
    before = stored_counts(case)
    with case.database.owner.begin() as connection:
        connection.execute(text("REVOKE INSERT ON audit_logs FROM aegis_app"))
    try:
        response = submit(admin.client, source, envelope("rollback"), "atomic")
        assert response.status_code == 503
    finally:
        with case.database.owner.begin() as connection:
            connection.execute(text("GRANT INSERT ON audit_logs TO aegis_app"))
    assert stored_counts(case) == before
    restored = accept(admin.client, source, envelope("rollback"), "atomic")
    assert restored["created_count"] == 1


@pytest.mark.parametrize(
    "limit",
    [
        "ingest_max_stored_events",
        "ingest_max_stored_bytes",
        "ingest_max_pending_events",
        "ingest_max_receipt_records",
    ],
)
def test_capacity_rejection_preserves_existing_receipts(
    case: Case, admin: Login, limit: str
) -> None:
    source = enroll(admin)
    first = accept(admin.client, source, envelope("already"), "original")
    before = stored_counts(case)
    client = case.client(case.database.settings.model_copy(update={limit: 1}))
    blocked = submit(client, source, envelope("new"))
    assert blocked.status_code == 503
    assert int(blocked.headers["retry-after"]) > 0
    repeated = accept(client, source, envelope("already"), "original")
    assert repeated == first
    assert stored_counts(case) == before


def test_stalled_pending_jobs_apply_backpressure(case: Case, admin: Login) -> None:
    source = enroll(admin)
    accept(admin.client, source, envelope("old"))
    with Session(case.database.owner) as session:
        job = session.scalar(select(OutboxJob))
        assert job is not None
        job.created_at = utcnow() - timedelta(hours=1)
        session.commit()
    before = stored_counts(case)
    response = submit(admin.client, source, envelope("new"))
    assert response.status_code == 503
    assert stored_counts(case) == before


def test_redis_limiter_outage_fails_closed_without_persisting_payload(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    url = make_url(case.database.settings.redis_url.get_secret_value()).set(password=random_token())
    client = case.client(
        case.database.settings.model_copy(
            update={"redis_url": SecretStr(url.render_as_string(hide_password=False))}
        )
    )
    response = submit(client, source, envelope("not-accepted"))
    assert response.status_code == 503
    assert response.json()["code"] == "limiter_unavailable"
    assert stored_counts(case)["RawEvent"] == 0
    assert accept(admin.client, source, envelope("not-accepted"))["created_count"] == 1


def test_duplicate_only_new_receipts_cannot_bypass_metadata_capacity(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    original = accept(admin.client, source, envelope("same"), "receipt-one")
    before = stored_counts(case)
    client = case.client(
        case.database.settings.model_copy(update={"ingest_max_receipt_records": 1})
    )
    rejected = submit(client, source, envelope("same"), "receipt-two")
    assert rejected.status_code == 503
    assert accept(client, source, envelope("same"), "receipt-one") == original
    assert stored_counts(case) == before


def test_rate_limit_is_shared_by_all_credentials_for_same_source(case: Case, admin: Login) -> None:
    source = enroll(admin)
    issued = admin.client.post(
        f"/api/v1/sources/{source.id}/credentials",
        json={"scopes": ["events:write"], "expires_in_days": 1},
        headers=admin.authorization,
    )
    assert issued.status_code == 201
    key = f"aegis:limit:ingest-source:{token_hash(source.id)}"
    redis = admin.client.app.state.redis
    # Seed only this test's unguessable source key; never scan or flush shared Redis.
    redis.set(key, 10, ex=30)
    try:
        for token in (source.token, issued.json()["token"]):
            response = admin.client.post(
                "/api/v1/events",
                json=envelope(),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Idempotency-Key": uuid4().hex,
                    "X-Forwarded-For": "192.0.2.10",
                },
            )
            assert response.status_code == 429
            assert int(response.headers["retry-after"]) > 0
        assert stored_counts(case)["RawEvent"] == 0
    finally:
        redis.delete(key)


def test_source_patch_requires_current_version_and_rejects_identity_changes(
    case: Case, admin: Login
) -> None:
    source = enroll(admin)
    path = f"/api/v1/sources/{source.id}"
    assert (
        admin.client.patch(path, json={"enabled": False}, headers=admin.authorization).status_code
        == 428
    )
    changed = admin.client.patch(
        path, json={"enabled": False}, headers={**admin.authorization, "If-Match": '"1"'}
    )
    assert changed.status_code == 200 and changed.headers["etag"] == '"2"'
    assert (
        admin.client.patch(
            path, json={"enabled": True}, headers={**admin.authorization, "If-Match": '"1"'}
        ).status_code
        == 412
    )
    assert (
        admin.client.patch(
            path, json={"mode": "replay"}, headers={**admin.authorization, "If-Match": '"2"'}
        ).status_code
        == 422
    )


def test_reenabling_source_requires_new_credentials(case: Case, admin: Login) -> None:
    source = enroll(admin)
    path = f"/api/v1/sources/{source.id}"
    for version, enabled in ((1, False), (2, True)):
        response = admin.client.patch(
            path,
            json={"enabled": enabled},
            headers={**admin.authorization, "If-Match": f'"{version}"'},
        )
        assert response.status_code == 200
    assert submit(admin.client, source, envelope()).status_code == 401
    issued = admin.client.post(f"{path}/credentials", json={}, headers=admin.authorization)
    assert issued.status_code == 201
    source.token = issued.json()["token"]
    assert accept(admin.client, source, envelope())["created_count"] == 1


@pytest.mark.parametrize(
    "role,expected", [("soc_manager", 200), ("soc_analyst", 403), ("read_only", 403)]
)
def test_ingestion_operator_status_requires_system_read(
    case: Case, admin: Login, role: str, expected: int
) -> None:
    source = enroll(admin)
    user = case.create_user(admin, role)
    principal = case.login(str(user["username"]), str(user["password"]))
    path = "/api/v1/system/ingestion"
    assert principal.client.get(path, headers=principal.authorization).status_code == expected
    assert admin.client.get(path, headers=source.authorization).status_code == 401
    assert admin.client.get(path).status_code == 401


def test_operator_status_counts_unique_events_receipts_and_capacity(
    case: Case, admin: Login
) -> None:
    from app.modules.ingestion.processing import process_event

    from .helper_ingestion import processing_database

    source = enroll(admin)
    receipt = accept(
        admin.client,
        source,
        {"events": [envelope("pending"), envelope("staged"), envelope("poison", raw="")]},
    )
    accept(admin.client, source, envelope("pending"))
    records = status(admin.client, source, receipt)["records"]
    database = processing_database(case)
    for record in records[1:]:
        process_event(database, case.database.settings, UUID(record["event_id"]), 1)
    with Session(case.database.owner) as session:
        pending = session.get(OutboxJob, UUID(records[0]["event_id"]))
        assert pending is not None
        pending.created_at = utcnow() - timedelta(seconds=90)
        session.commit()
    response = admin.client.get("/api/v1/system/ingestion", headers=admin.authorization)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    view = response.json()
    counts = stored_counts(case)
    assert view["retained_events"] == counts["capacity_events"] == 3
    assert view["receipt_records"] == counts["capacity_receipts"] == 4
    assert view["payload_bytes"] == counts["capacity_bytes"] > 0
    assert view["states"] == {"pending": 1, "processing": 0, "staged": 1, "quarantined": 1}
    assert 90 <= view["oldest_pending_seconds"] < 110
    settings = case.database.settings
    assert view["limits"] == {
        "stored_events": settings.ingest_max_stored_events,
        "receipt_records": settings.ingest_max_receipt_records,
        "payload_bytes": settings.ingest_max_stored_bytes,
        "pending_events": settings.ingest_max_pending_events,
        "oldest_pending_seconds": settings.ingest_max_oldest_pending_seconds,
    }
    assert source.token not in response.text and "raw_event" not in response.text
