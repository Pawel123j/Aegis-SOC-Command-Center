"""Real PostgreSQL ingestion, atomic evidence, scope isolation and read-only UEBA."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core import permissions
from app.core.permissions import Permission, Role
from app.modules.entities.models import EntityIdentity
from app.modules.events.clickhouse import ClickHouseEvents
from app.modules.ueba import queries

from .helper_correlation import auth_event, normalize_inputs
from .helper_ingestion import Source, enroll
from .helpers import Case, Login
from .test_attack_timeline_security import stored_counts
from .test_initial_alerts import user

pytestmark = pytest.mark.integration
START = datetime(2026, 9, 1, 9, tzinfo=UTC)
DAY = "2026-09-29"


def observed(day: int, hour: int = 9, **values: Any) -> dict[str, Any]:
    return auth_event(
        START.replace(hour=hour) + timedelta(days=day),
        "success",
        event={"category": "authentication", "type": "start", "outcome": "success"},
        **values,
    )


def seed(
    case: Case, admin: Login, *, replay: tuple[UUID, UUID] | None = None, complete: bool = False
) -> tuple[Source, UUID, list[UUID]]:
    events = [observed(i // 3) for i in range(21)] if complete else [observed(0)]
    events.append(observed(28, 2, source={"ip": "192.0.2.2"}))
    source, ids = normalize_inputs(case, admin, events, replay=replay)
    with Session(case.database.runtime) as db:
        identifier = db.scalar(
            select(EntityIdentity.id).where(
                EntityIdentity.source_id == source.id,
                EntityIdentity.kind == "host",
            )
        )
    assert identifier is not None
    return source, identifier, ids


def response(principal: Login, entity: UUID, **params: Any) -> Any:
    return principal.client.get(
        f"/api/v1/entities/{entity}/ueba",
        params={"day": DAY, **params},
        headers=principal.authorization,
    )


def read(principal: Login, entity: UUID, **params: Any) -> dict[str, Any]:
    result = response(principal, entity, **params)
    assert result.status_code == 200, result.text
    assert result.headers["cache-control"] == "no-store"
    return dict(result.json())


def proof_response(
    principal: Login, entity: UUID, event_id: UUID, digest: str, **params: Any
) -> Any:
    return principal.client.get(
        f"/api/v1/entities/{entity}/ueba/events/{event_id}",
        params={"day": DAY, "document_sha256": digest, **params},
        headers=principal.authorization,
    )


def test_real_complete_baseline_proofs_and_reads_never_mutate_domain(
    case: Case, admin: Login
) -> None:
    _, identifier, ids = seed(case, admin, complete=True)
    before = stored_counts(case)
    result = read(admin, identifier)
    assert result["status"] == "ready" and result["score"] == 40
    assert result["policy_version"] == "ueba-statistics-v1"
    assert result["baseline"]["eligible_events"] == 21
    assert result["baseline"]["active_days"] == 7
    assert result["observation"]["eligible_events"] == 1
    assert result["scope"] == {"mode": "live", "dataset_id": None, "run_id": None}
    assert datetime.fromisoformat(result["as_of"].replace("Z", "+00:00")).tzinfo is not None
    with Session(case.database.runtime) as db:
        expected_hash = db.scalar(
            text("SELECT document_sha256 FROM normalized_events WHERE event_id=:id"),
            {"id": ids[-1]},
        )
    unusual = [item for item in result["indicators"] if item["status"] == "anomaly"]
    assert {item["id"] for item in unusual} == {"unusual_login_hour", "new_login_ip"}
    assert all(item["evidence"][0]["document_sha256"] == expected_hash for item in unusual)
    assert all(item["evidence"][0]["event_id"] == str(ids[-1]) for item in unusual)
    again = read(admin, identifier)
    result.pop("as_of")
    again.pop("as_of")
    assert result == again and stored_counts(case) == before


def test_cold_start_empty_observation_and_no_implicit_training(case: Case, admin: Login) -> None:
    _, identifier, _ = seed(case, admin)
    result = read(admin, identifier, day="2026-09-28")
    assert result["status"] == "cold_start" and result["score"] is None
    assert result["baseline"]["eligible_events"] == 1
    assert result["observation"]["event_count"] == 0
    assert not any(item["status"] == "anomaly" for item in result["indicators"])


def test_old_missing_index_in_same_source_suppresses_all_anomalies(
    case: Case,
    admin: Login,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, identifier, _ = seed(case, admin, complete=True)
    with monkeypatch.context() as patch:
        patch.setattr("app.modules.normalization.processing.index_event", lambda *a, **k: 0)
        normalize_inputs(case, admin, [observed(5, host={"id": "different-host"})], source=source)
    before = stored_counts(case)
    result = read(admin, identifier)
    assert result["status"] == "index_pending" and result["pending_events"] == 1
    assert result["score"] is None and all(
        item["status"] != "anomaly" for item in result["indicators"]
    )
    assert stored_counts(case) == before


def test_other_source_missing_index_does_not_block_profile(
    case: Case,
    admin: Login,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, identifier, _ = seed(case, admin, complete=True)
    with monkeypatch.context() as patch:
        patch.setattr("app.modules.normalization.processing.index_event", lambda *a, **k: 0)
        normalize_inputs(case, admin, [observed(5)])
    assert read(admin, identifier)["status"] == "ready"


def test_live_and_replay_require_exact_identity_scope(case: Case, admin: Login) -> None:
    _, live, _ = seed(case, admin)
    scope = uuid4(), uuid4()
    _, replay, _ = seed(case, admin, replay=scope)
    params = {"mode": "replay", "dataset_id": str(scope[0]), "run_id": str(scope[1])}
    assert read(admin, replay, **params)["scope"] == params
    assert response(admin, replay).status_code == 404
    assert response(admin, live, **params).status_code == 404
    assert response(admin, replay, **{**params, "run_id": str(uuid4())}).status_code == 404


@pytest.mark.parametrize("kind", ["ip", "process"])
def test_unsupported_profile_kinds_are_explicit_not_integrity_failures(
    case: Case, admin: Login, kind: str
) -> None:
    source, _ = normalize_inputs(case, admin, [observed(0, process={"name": "sudo"})])
    with Session(case.database.runtime) as db:
        identifier = db.scalar(select(EntityIdentity.id).where(EntityIdentity.kind == kind))
    assert identifier is not None and source.id is not None
    result = read(admin, identifier)
    assert (
        result["status"] == "unsupported" and result["score"] is None and result["indicators"] == []
    )


@pytest.mark.parametrize(
    "missing", [Permission.EVENTS_READ, Permission.ALERTS_READ, Permission.INCIDENTS_READ]
)
def test_all_three_reader_permissions_are_required(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch, missing: Permission
) -> None:
    _, identifier, _ = seed(case, admin)
    reader = user(case, admin, "read_only")
    restricted = dict(permissions.ROLE_PERMISSIONS)
    restricted[Role.READ_ONLY] = restricted[Role.READ_ONLY] - {missing}
    monkeypatch.setattr(permissions, "ROLE_PERMISSIONS", restricted)
    result = response(reader, identifier)
    assert result.status_code == 403 and result.json()["code"] == "forbidden"
    assert result.headers["cache-control"] == "no-store"

    proof = proof_response(reader, identifier, uuid4(), "0" * 64)
    assert proof.status_code == 403 and proof.json()["code"] == "forbidden"


@pytest.mark.parametrize("credential", ["anonymous", "source"])
def test_nonuser_credentials_cannot_read_reports(case: Case, admin: Login, credential: str) -> None:
    _, identifier, _ = seed(case, admin)
    headers = {} if credential == "anonymous" else enroll(admin).authorization
    result = case.client().get(
        f"/api/v1/entities/{identifier}/ueba", params={"day": DAY}, headers=headers
    )
    assert result.status_code == 401


@pytest.mark.parametrize(
    "params",
    [
        {"day": "2299-01-01"},
        {"day": "1970-01-01"},
        {"mode": "replay"},
        {"dataset_id": str(UUID(int=1))},
        {"from": "2026-01-01"},
        {"day": "invalid"},
    ],
)
def test_invalid_window_and_scope_are_rejected(
    case: Case, admin: Login, params: dict[str, str]
) -> None:
    result = response(admin, uuid4(), **params)
    assert result.status_code == 422 and result.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("bound", ["MAX_EVENTS", "MAX_BYTES"])
def test_bound_failure_never_returns_partial_healthy_report(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch, bound: str
) -> None:
    _, identifier, _ = seed(case, admin)
    monkeypatch.setattr(queries, bound, 1)
    before = stored_counts(case)
    result = response(admin, identifier)
    assert result.status_code == 409 and result.json()["code"] == "ueba_limit_exceeded"
    assert "indicators" not in result.json() and stored_counts(case) == before


@pytest.mark.parametrize(
    "table,assignment",
    [
        ("normalized_events", "document_sha256=repeat('a',64)"),
        ("raw_events", "payload_hash=repeat('a',64)"),
        ("entity_index_receipts", "observation_count=0"),
        ("entity_observations", "attributes='{}'::jsonb"),
        ("entity_observations", "timestamp=timestamp + interval '1 second'"),
        ("entity_identities", "identity_basis='event_local'"),
    ],
)
def test_original_and_index_corruption_fails_closed(
    case: Case, admin: Login, table: str, assignment: str
) -> None:
    _, identifier, ids = seed(case, admin)
    # Deliberate corruption is confined to this generated test database and owner.
    with case.database.owner.begin() as db:
        db.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER USER"))
        column = "id" if table in {"raw_events", "entity_identities"} else "event_id"
        value = identifier if table == "entity_identities" else ids[-1]
        db.execute(text(f"UPDATE {table} SET {assignment} WHERE {column}=:id"), {"id": value})
        db.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER USER"))
    result = response(admin, identifier)
    assert result.status_code == 409 and result.json()["code"] == "ueba_integrity_mismatch"


def test_daily_ueba_is_rate_limited_per_authenticated_reader(case: Case, admin: Login) -> None:
    for _ in range(30):
        assert response(admin, uuid4()).status_code == 404
    result = response(admin, uuid4())
    assert result.status_code == 429 and result.headers["cache-control"] == "no-store"


def test_same_user_in_actor_and_target_roles_counts_unique_events(case: Case, admin: Login) -> None:
    source, _ = normalize_inputs(
        case, admin, [observed(0, user={"name": "alice", "target": {"name": "alice"}})]
    )
    with Session(case.database.runtime) as db:
        identifier = db.scalar(
            select(EntityIdentity.id).where(
                EntityIdentity.kind == "user", EntityIdentity.source_id == source.id
            )
        )
    assert identifier is not None
    result = read(admin, identifier)
    assert result["baseline"]["event_count"] == result["baseline"]["eligible_events"] == 1


def test_windows_parser_missing_target_keeps_subject_out_of_login_statistics(
    case: Case, admin: Login
) -> None:
    events = [
        {
            "source_type": "windows_auth",
            "timestamp": (START + timedelta(days=day)).isoformat(),
            "raw_event": {
                "EventID": 4624,
                "Computer": "server",
                "EventData": {
                    "SubjectUserSid": "S-1-5-18",
                    "SubjectUserName": "SYSTEM",
                    "IpAddress": "192.0.2.1",
                },
            },
        }
        for day in [*(i // 3 for i in range(21)), 28]
    ]
    source, _ = normalize_inputs(case, admin, events)
    with Session(case.database.runtime) as db:
        identifier = db.scalar(
            select(EntityIdentity.id).where(
                EntityIdentity.kind == "user", EntityIdentity.source_id == source.id
            )
        )
    assert identifier is not None
    result = read(admin, identifier)
    assert result["status"] == "ready" and result["baseline"]["eligible_events"] == 21
    for item in result["indicators"]:
        if item["id"] in {"unusual_login_hour", "new_login_ip", "failed_login_burst"}:
            assert item["baseline_event_count"] == item["observed_count"] == 0
            assert item["status"] != "anomaly"


@pytest.mark.parametrize("replay", [False, True])
def test_original_proof_is_verified_without_using_archive(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch, replay: bool
) -> None:
    scope = (uuid4(), uuid4()) if replay else None
    _, identifier, ids = seed(case, admin, replay=scope, complete=True)
    params = (
        {"mode": "replay", "dataset_id": str(scope[0]), "run_id": str(scope[1])} if scope else {}
    )
    result = read(admin, identifier, **params)
    digest = next(item for item in result["indicators"] if item["id"] == "new_login_ip")[
        "evidence"
    ][0]["document_sha256"]
    with Session(case.database.runtime) as db:
        original = db.scalar(
            text("SELECT document FROM normalized_events WHERE event_id=:id"), {"id": ids[-1]}
        )

    def no_archive(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("UEBA proof must use the verified PostgreSQL original")

    monkeypatch.setattr(ClickHouseEvents, "get_event", no_archive)
    before = stored_counts(case)
    proof = proof_response(admin, identifier, ids[-1], digest, **params)
    assert proof.status_code == 200, proof.text
    assert proof.headers["cache-control"] == "no-store" and proof.json() == original
    assert stored_counts(case) == before


@pytest.mark.parametrize("change", ["hash", "event", "day", "normal_event"])
def test_stale_or_unrelated_proof_requires_refresh(case: Case, admin: Login, change: str) -> None:
    _, identifier, ids = seed(case, admin, complete=True)
    result = read(admin, identifier)
    digest = next(item for item in result["indicators"] if item["id"] == "new_login_ip")[
        "evidence"
    ][0]["document_sha256"]
    event_id = uuid4() if change == "event" else ids[0] if change == "normal_event" else ids[-1]
    proof = proof_response(
        admin,
        identifier,
        event_id,
        "0" * 64 if change == "hash" else digest,
        **({"day": "2026-09-28"} if change == "day" else {}),
    )
    assert proof.status_code == 409 and proof.json()["code"] == "ueba_changed"


@pytest.mark.parametrize("digest", ["", "not-a-hash", "a" * 63, "A" * 64])
def test_proof_requires_a_canonical_hash(admin: Login, digest: str) -> None:
    assert proof_response(admin, uuid4(), uuid4(), digest).status_code == 422
