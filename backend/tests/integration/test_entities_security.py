"""Independent authority, cursor, append-only storage and original evidence checks."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import timedelta
from threading import Event
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core import permissions
from app.core.permissions import Permission, Role
from app.infrastructure.database import ADMIN_LOCK_ID, utcnow
from app.modules.audit.models import AuditLog
from app.modules.auth.models import AuthSession
from app.modules.entities import indexing
from app.modules.entities.identity import IDENTITY_POLICY, extract_entity_descriptors
from app.modules.entities.models import EntityIdentity
from app.modules.ingestion.models import RawEvent
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.models import NormalizedEvent
from app.modules.users.models import User

from .helper_entities import WINDOW, counts, read
from .helper_ingestion import enroll, processing_database
from .helpers import Case, Login, migrate
from .test_initial_alerts import alerts, detect_once, normalize_events, powershell, user

pytestmark = pytest.mark.integration
BASE = "/api/v1/entities"
TABLES = (
    "entity_identities",
    "entity_index_receipts",
    "entity_observations",
    "entity_alert_receipts",
    "alert_event_references",
)


def backfill(principal: Login) -> Any:
    return principal.client.post(
        BASE + "/backfill",
        json={"limit": 100},
        headers=principal.authorization,
    )


def seed(case: Case, admin: Login, count: int = 1) -> list[UUID]:
    identifiers = normalize_events(case, admin, [powershell() for _ in range(count)])
    result = detect_once(processing_database(case), case.database.settings)
    assert result["alerts"] == count
    return identifiers


def legacy(
    case: Case,
    admin: Login,
    monkeypatch: pytest.MonkeyPatch,
    count: int = 1,
) -> list[UUID]:
    """Authentic old evidence without the new write hooks, only in this test DB."""
    with monkeypatch.context() as patch:
        patch.setattr("app.modules.normalization.processing.index_event", lambda *a, **k: 0)
        patch.setattr("app.modules.detections.processing.index_alert", lambda *a, **k: None)
        return seed(case, admin, count)


def audit_count(case: Case) -> int:
    with Session(case.database.runtime) as db:
        return int(db.scalar(select(func.count()).select_from(AuditLog)) or 0)


def routes(identifier: str, event_id: UUID) -> list[str]:
    return [
        "",
        f"/by-event/{event_id}",
        f"/{identifier}",
        *(f"/{identifier}/{kind}" for kind in ("events", "alerts", "incidents", "related")),
    ]


@pytest.mark.parametrize("credential", ["anonymous", "source"])
def test_no_entity_route_accepts_anonymous_or_ingestion_credentials(
    case: Case,
    admin: Login,
    credential: str,
) -> None:
    ids = seed(case, admin)
    identifier = read(admin)["items"][0]["id"]
    headers = {} if credential == "anonymous" else enroll(admin).authorization
    before = counts(case)
    client = case.client()
    for path in routes(identifier, ids[0]):
        response = client.get(BASE + path, params=WINDOW, headers=headers)
        assert response.status_code == 401, response.text
        assert response.json()["code"] == "unauthorized"
        assert response.headers["cache-control"] == "no-store"
    response = client.post(BASE + "/backfill", json={"limit": 1}, headers=headers)
    assert response.status_code == 401
    assert counts(case) == before


@pytest.mark.parametrize(
    "missing", [Permission.EVENTS_READ, Permission.ALERTS_READ, Permission.INCIDENTS_READ]
)
def test_each_entity_read_requires_all_three_soc_permissions(
    case: Case,
    admin: Login,
    monkeypatch: pytest.MonkeyPatch,
    missing: Permission,
) -> None:
    ids = seed(case, admin)
    identifier = read(admin)["items"][0]["id"]
    principal = user(case, admin, "read_only")
    restricted = dict(permissions.ROLE_PERMISSIONS)
    restricted[Role.READ_ONLY] = restricted[Role.READ_ONLY] - {missing}
    monkeypatch.setattr(permissions, "ROLE_PERMISSIONS", restricted)
    before = counts(case)
    for path in routes(identifier, ids[0]):
        response = principal.client.get(BASE + path, params=WINDOW, headers=principal.authorization)
        assert response.status_code == 403, response.text
        assert response.json()["code"] == "forbidden"
        assert response.headers["cache-control"] == "no-store"
        assert "items" not in response.json()
    assert counts(case) == before


@pytest.mark.parametrize("role", ["soc_manager", "soc_analyst", "read_only"])
def test_only_administrator_can_backfill_history(
    case: Case,
    admin: Login,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
) -> None:
    legacy(case, admin, monkeypatch)
    principal = user(case, admin, role)
    before = counts(case)
    response = backfill(principal)
    assert response.status_code == 403 and response.json()["code"] == "forbidden"
    assert counts(case) == before


@pytest.mark.parametrize("change", ["role", "disabled", "revoked", "absolute", "idle"])
def test_backfill_rechecks_current_user_and_session_after_authority_lock(
    case: Case,
    admin: Login,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    legacy(case, admin, monkeypatch)
    operator = user(case, admin, "admin")
    before = counts(case)
    reached = Event()
    engine = operator.client.app.state.database.engine

    def observe(
        connection: Any,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        if "pg_advisory_xact_lock" in statement:
            reached.set()

    event.listen(engine, "before_cursor_execute", observe)
    try:
        with case.database.owner.connect() as blocker:
            blocker.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": ADMIN_LOCK_ID})
            with ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(backfill, operator)
                try:
                    assert reached.wait(timeout=3), "Backfill did not reach authority lock"
                    with Session(case.database.owner) as db:
                        identity, now = UUID(operator.user_id), utcnow()
                        if change in {"role", "disabled"}:
                            values = (
                                {"role": Role.READ_ONLY} if change == "role" else {"enabled": False}
                            )
                            db.execute(update(User).where(User.id == identity).values(**values))
                        else:
                            values = {
                                "revoked": {"revoked_at": now},
                                "absolute": {"absolute_expires_at": now - timedelta(seconds=1)},
                                "idle": {
                                    "last_seen_at": now
                                    - timedelta(
                                        seconds=case.database.settings.session_idle_seconds + 10
                                    )
                                },
                            }[change]
                            db.execute(
                                update(AuthSession)
                                .where(AuthSession.user_id == identity)
                                .values(**values)
                            )
                        db.commit()
                finally:
                    blocker.rollback()
                response = pending.result(timeout=10)
    finally:
        event.remove(engine, "before_cursor_execute", observe)
    assert response.status_code == 403 and response.json()["code"] == "forbidden", response.text
    assert counts(case) == before


@pytest.mark.parametrize(
    "change", ["signature", "user", "resource", "kind", "q", "limit", "from", "mode"]
)
def test_entity_cursor_cannot_be_modified_or_transferred_to_other_query_or_principal(
    case: Case,
    admin: Login,
    change: str,
) -> None:
    ids = seed(case, admin, 2)
    first = read(admin, limit=1)
    cursor = first["next_cursor"]
    assert cursor
    principal = admin
    path = BASE
    params: dict[str, Any] = {**WINDOW, "limit": 1, "cursor": cursor}
    if change == "signature":
        position = cursor.index(".") + 1
        params["cursor"] = (
            cursor[:position] + ("A" if cursor[position] != "A" else "B") + cursor[position + 1 :]
        )
    elif change == "user":
        principal = user(case, admin, "read_only")
    elif change == "resource":
        path += f"/by-event/{ids[0]}"
    elif change == "kind":
        params["kind"] = "host"
    elif change == "q":
        params["q"] = "host"
    elif change == "limit":
        params["limit"] = 2
    elif change == "from":
        params["from"] = "2026-10-01T00:00:01Z"
    else:
        params.update(mode="replay", dataset_id=str(uuid4()), run_id=str(uuid4()))
    before = counts(case)
    response = principal.client.get(path, params=params, headers=principal.authorization)
    assert response.status_code == 422 and response.json()["code"] == "invalid_cursor", (
        response.text
    )
    assert counts(case) == before


def test_collection_cursor_is_bound_to_entity_and_collection(case: Case, admin: Login) -> None:
    seed(case, admin, 2)
    profiles = read(admin)["items"]
    host = next(item for item in profiles if item["kind"] == "host")
    principal = next(item for item in profiles if item["kind"] == "user")
    page = read(admin, f"/{host['id']}/events", limit=1)
    assert page["next_cursor"]
    for path in (f"/{principal['id']}/events", f"/{host['id']}/alerts"):
        response = admin.client.get(
            BASE + path,
            params={**WINDOW, "limit": 1, "cursor": page["next_cursor"]},
            headers=admin.authorization,
        )
        assert response.status_code == 422 and response.json()["code"] == "invalid_cursor"


def test_literal_search_does_not_interpret_sql_or_wildcards(case: Case, admin: Login) -> None:
    seed(case, admin)
    before = counts(case)
    assert read(admin)["total"] > 0
    for query in ("%", "_", "' OR 1=1 --", "x'; DROP TABLE entity_identities; --"):
        result = read(admin, q=query)
        assert result["total"] == 0 and result["items"] == []
    assert counts(case) == before


def test_nil_replay_dataset_is_rejected_before_query(case: Case, admin: Login) -> None:
    before = counts(case)
    response = admin.client.get(
        BASE,
        params={**WINDOW, "mode": "replay", "dataset_id": str(UUID(int=0)), "run_id": str(uuid4())},
        headers=admin.authorization,
    )
    assert response.status_code == 422, response.text
    assert counts(case) == before


def test_database_rejects_nil_replay_dataset(case: Case, admin: Login) -> None:
    seed(case, admin)
    before = counts(case)
    with Session(case.database.runtime) as db:
        original = db.scalar(select(EntityIdentity))
        assert original is not None
        db.add(
            EntityIdentity(
                id=uuid4(),
                key_sha256="0" * 64,
                kind=original.kind,
                label=original.label,
                identity_policy=original.identity_policy,
                identity_basis=original.identity_basis,
                canonical_identity=deepcopy(original.canonical_identity),
                source_id=original.source_id,
                mode="replay",
                dataset_id=UUID(int=0),
                run_id=uuid4(),
            )
        )
        with pytest.raises(DBAPIError) as rejected:
            db.commit()
        assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
        db.rollback()
    assert counts(case) == before


def test_runtime_grants_allow_append_and_read_only_and_functions_are_not_public(
    case: Case,
    admin: Login,
) -> None:
    seed(case, admin)
    before = counts(case)
    with case.database.runtime.connect() as db:
        for table in TABLES:
            for privilege in (
                "SELECT",
                "INSERT",
                "UPDATE",
                "DELETE",
                "TRUNCATE",
                "REFERENCES",
                "TRIGGER",
            ):
                allowed = db.scalar(
                    text("SELECT has_table_privilege(current_user,:table,:privilege)"),
                    {"table": table, "privilege": privilege},
                )
                assert bool(allowed) is (privilege in {"SELECT", "INSERT"})
            column = (
                "id"
                if table == "entity_identities"
                else "alert_id"
                if table == "entity_alert_receipts"
                else "event_id"
            )
            for statement in (
                f"UPDATE {table} SET {column}={column}",
                f"DELETE FROM {table}",
                f"TRUNCATE {table} CASCADE",
            ):
                db.rollback()
                with pytest.raises(DBAPIError) as rejected:
                    db.execute(text(statement))
                assert getattr(rejected.value.orig, "sqlstate", None) == "42501"
                db.rollback()
    with case.database.owner.connect() as db:
        for suffix in ("immutable", "validate", "complete"):
            name = f"public.aegis_entities_{suffix}()"
            assert not db.scalar(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_proc p, "
                    "LATERAL aclexplode(p.proacl) a WHERE p.oid=CAST(:name AS regprocedure) "
                    "AND a.grantee=0 AND a.privilege_type='EXECUTE')"
                ),
                {"name": name},
            )
    assert counts(case) == before


def test_owner_cannot_rewrite_delete_or_truncate_entity_evidence(case: Case, admin: Login) -> None:
    seed(case, admin)
    before = counts(case)
    assert all(before[table] > 0 for table in TABLES)
    with case.database.owner.connect() as db:
        for table in TABLES:
            column = (
                "id"
                if table == "entity_identities"
                else "alert_id"
                if table == "entity_alert_receipts"
                else "event_id"
            )
            for statement in (
                f"UPDATE {table} SET {column}={column}",
                f"DELETE FROM {table}",
                f"TRUNCATE {table} CASCADE",
            ):
                with pytest.raises(DBAPIError) as rejected:
                    db.execute(text(statement))
                assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
                db.rollback()
    assert counts(case) == before


@pytest.mark.parametrize("kind", ["event", "alert"])
def test_incomplete_receipt_cannot_commit(
    case: Case,
    admin: Login,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    ids = legacy(case, admin, monkeypatch)
    before = counts(case)
    with Session(case.database.runtime) as db:
        if kind == "event":
            snapshot = db.get(NormalizedEvent, ids[0])
            assert snapshot is not None
            db.execute(
                text(
                    "INSERT INTO entity_index_receipts"
                    "(event_id,document_sha256,identity_policy,observation_count) "
                    "VALUES (:event,:hash,:policy,1)"
                ),
                {"event": ids[0], "hash": snapshot.document_sha256, "policy": IDENTITY_POLICY},
            )
        else:
            db.execute(
                text(
                    "INSERT INTO entity_alert_receipts(alert_id,contributor_count) "
                    "VALUES (:alert,1)"
                ),
                {"alert": alerts(case)[0].id},
            )
        with pytest.raises(DBAPIError) as rejected:
            db.commit()
        assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
        db.rollback()
    assert counts(case) == before


@pytest.mark.parametrize("change", ["hash", "time", "source", "scope", "policy"])
def test_observation_cannot_reference_foreign_or_inconsistent_evidence(
    case: Case,
    admin: Login,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    ids = legacy(case, admin, monkeypatch)
    other_source = UUID(enroll(admin).id)
    before = counts(case)
    with Session(case.database.runtime) as db:
        snapshot = db.get(NormalizedEvent, ids[0])
        assert snapshot is not None
        descriptor = extract_entity_descriptors(snapshot.document)[0]
        identity = EntityIdentity(
            id=descriptor.entity_id,
            key_sha256=descriptor.key_sha256,
            kind=descriptor.entity_type,
            label=descriptor.label,
            identity_policy="different-policy" if change == "policy" else IDENTITY_POLICY,
            identity_basis=descriptor.identity_strength,
            canonical_identity=descriptor.canonical_key,
            source_id=other_source if change == "source" else UUID(snapshot.document["source_id"]),
            mode="replay" if change == "scope" else "live",
            dataset_id=uuid4() if change == "scope" else None,
            run_id=uuid4() if change == "scope" else UUID(int=0),
        )
        db.add(identity)
        db.flush()
        db.execute(
            text(
                "INSERT INTO entity_index_receipts"
                "(event_id,document_sha256,identity_policy,observation_count) "
                "VALUES (:event,:hash,:policy,1)"
            ),
            {"event": ids[0], "hash": snapshot.document_sha256, "policy": IDENTITY_POLICY},
        )
        with pytest.raises(DBAPIError) as rejected:
            db.execute(
                text(
                    "INSERT INTO entity_observations"
                    "(entity_id,event_id,role,timestamp,document_sha256,attributes) "
                    "VALUES (:entity,:event,'host',:timestamp,:hash,'{}'::jsonb)"
                ),
                {
                    "entity": identity.id,
                    "event": ids[0],
                    "timestamp": snapshot.timestamp + timedelta(seconds=1)
                    if change == "time"
                    else snapshot.timestamp,
                    "hash": "0" * 64 if change == "hash" else snapshot.document_sha256,
                },
            )
        assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
        db.rollback()
    assert counts(case) == before


def test_alert_reference_cannot_attach_an_event_that_was_not_original_contributor(
    case: Case,
    admin: Login,
) -> None:
    seed(case, admin)
    unrelated = normalize_events(case, admin, [powershell("powershell -Command Get-Date")])[0]
    before = counts(case)
    with Session(case.database.runtime) as db:
        snapshot = db.get(NormalizedEvent, unrelated)
        assert snapshot is not None
        with pytest.raises(DBAPIError) as rejected:
            db.execute(
                text(
                    "INSERT INTO alert_event_references(alert_id,event_id,document_sha256) "
                    "VALUES (:alert,:event,:hash)"
                ),
                {"alert": alerts(case)[0].id, "event": unrelated, "hash": snapshot.document_sha256},
            )
        assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
        db.rollback()
    assert counts(case) == before


@pytest.mark.parametrize(
    "change", ["normalized_hash", "raw_hash", "raw_event", "source_id", "received_at"]
)
def test_backfill_rejects_forged_original_proof_and_rolls_back_entire_batch(
    case: Case,
    admin: Login,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    ids = legacy(case, admin, monkeypatch, 2)
    with Session(case.database.owner) as db:
        snapshots = list(
            db.scalars(
                select(NormalizedEvent)
                .where(NormalizedEvent.event_id.in_(ids))
                .order_by(NormalizedEvent.processed_at, NormalizedEvent.event_id)
            )
        )
        last = snapshots[-1]
        raw = db.get(RawEvent, last.event_id)
        assert raw is not None
        table = "raw_events" if change == "raw_hash" else "normalized_events"
        db.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER USER"))
        if change == "raw_hash":
            raw.payload_hash = "0" * 64
        elif change == "normalized_hash":
            last.document_sha256 = "0" * 64
        else:
            document = deepcopy(last.document)
            if change == "raw_event":
                document["raw_event"]["EventData"]["CommandLine"] = "forged"
            elif change == "source_id":
                document["source_id"] = str(uuid4())
            else:
                document["received_at"] = (raw.received_at - timedelta(seconds=1)).isoformat()
            last.document = document
            last.document_sha256 = hashlib.sha256(canonical_json(document)).hexdigest()
        db.flush()
        db.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER USER"))
        db.commit()
    before, audits = counts(case), audit_count(case)
    response = backfill(admin)
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "entity_evidence_integrity_mismatch"
    assert counts(case) == before and audit_count(case) == audits
    assert all(value == 0 for value in before.values())


def test_backfill_audit_failure_rolls_back_all_index_writes(
    case: Case,
    admin: Login,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy(case, admin, monkeypatch)
    before, audits = counts(case), audit_count(case)
    attempted: list[dict[str, int]] = []

    def fail_audit(db: Session, *args: Any, **kwargs: Any) -> None:
        attempted.append(
            {table: int(db.scalar(text(f"SELECT count(*) FROM {table}")) or 0) for table in TABLES}
        )
        raise RuntimeError("test-only audit failure")

    monkeypatch.setattr(indexing, "append_audit", fail_audit)
    response = backfill(admin)
    # The outer telemetry middleware intentionally returns a safe HTTP error.
    assert response.status_code == 500 and response.json()["code"] == "internal_error"
    assert "test-only audit failure" not in response.text
    assert len(attempted) == 1 and all(value > 0 for value in attempted[0].values())
    assert all(value == 0 for value in before.values())
    assert counts(case) == before and audit_count(case) == audits


def test_downgrade_refuses_nonempty_entity_history(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Remove the empty newer layer before producing authentic entity-only history.
    migrate(case.database.owner, "0010_entities", downgrade=True)
    with monkeypatch.context() as patch:
        patch.setattr(
            "app.modules.detections.processing._intelligence_evaluation", lambda *_: (None, None)
        )
        patch.setattr("app.modules.risk.inputs.risk_contexts", lambda *_: ([], {}))
        ids = seed(case, admin)
    before = counts(case)
    with pytest.raises(DBAPIError) as rejected:
        migrate(case.database.owner, "0009_sigma", downgrade=True)
    assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
    assert "Entity history exists" in str(rejected.value)
    assert counts(case) == before
    with case.database.runtime.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "0010_entities"
    migrate(case.database.owner)
    assert counts(case) == before
    assert read(admin, f"/by-event/{ids[0]}")["total"] > 0


def test_empty_entity_schema_can_downgrade_and_upgrade_without_touching_existing_tables(
    case: Case,
    admin: Login,
) -> None:
    assert all(value == 0 for value in counts(case).values())
    audits = audit_count(case)
    migrate(case.database.owner, "0009_sigma", downgrade=True)
    migrate(case.database.owner)
    assert all(value == 0 for value in counts(case).values())
    assert audit_count(case) == audits
    with case.database.runtime.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "0011_intelligence"
