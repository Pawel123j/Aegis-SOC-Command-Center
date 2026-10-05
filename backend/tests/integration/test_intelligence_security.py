"""Independent local IOC authority, original proof and PostgreSQL integrity checks."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
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
from app.modules.ingestion.schemas import canonical_json
from app.modules.intelligence import matching
from app.modules.intelligence.models import IntEventMatch, IntEventReceipt, IOCIdentity, IOCRevision
from app.modules.intelligence.normalization import NORMALIZATION_VERSION
from app.modules.normalization.models import NormalizedEvent
from app.modules.normalization.schemas import NormalizedSecurityEvent
from app.modules.users.models import User

from .helper_correlation import auth_event, normalize_inputs
from .helper_ingestion import enroll, processing_database
from .helper_intelligence import BASE, counts, create
from .helpers import Case, Login
from .test_initial_alerts import alerts, detect_once, user

pytestmark = pytest.mark.integration
START = datetime(2026, 10, 1, 12, tzinfo=UTC)
TABLES = ("ioc_identities", "ioc_revisions", "int_event_receipts", "int_event_matches")


def backfill(principal: Login, limit: int = 100) -> Any:
    return principal.client.post(
        BASE + "/backfill", json={"limit": limit}, headers=principal.authorization
    )


def seed(case: Case, admin: Login) -> tuple[dict[str, Any], UUID]:
    item = create(admin, "192.0.2.1", "ip", reputation="malicious", confidence=90)
    _, identifiers = normalize_inputs(case, admin, [auth_event(START)])
    result = detect_once(processing_database(case), case.database.settings)
    assert result["alerts"] == 1 and len(alerts(case)) == 1
    return item, identifiers[0]


def receipt(snapshot: NormalizedEvent, count: int = 0) -> IntEventReceipt:
    document = snapshot.document
    return IntEventReceipt(
        event_id=snapshot.event_id,
        document_sha256=snapshot.document_sha256,
        normalization_version=NORMALIZATION_VERSION,
        mode=document["mode"],
        dataset_id=UUID(document["dataset_id"]) if document["mode"] == "replay" else None,
        run_id=UUID(document["run_id"]),
        match_count=count,
        evaluated_at=utcnow(),
    )


def match(snapshot: NormalizedEvent, revision: IOCRevision) -> IntEventMatch:
    return IntEventMatch(
        id=uuid4(),
        event_id=snapshot.event_id,
        ioc_id=revision.ioc_id,
        revision_id=revision.id,
        field="source.ip",
        observed_value="192.0.2.1",
        canonical_value="192.0.2.1",
        revision_snapshot=deepcopy(revision.document),
        revision_snapshot_sha256=revision.document_sha256,
    )


def next_revision(original: IOCRevision, **changes: Any) -> IOCRevision:
    identifier = uuid4()
    document = {
        **deepcopy(original.document),
        "revision_id": str(identifier),
        "revision": original.revision + 1,
        **changes,
    }
    canonical = canonical_json(document)
    return IOCRevision(
        id=identifier,
        ioc_id=original.ioc_id,
        revision=original.revision + 1,
        document=document,
        canonical_document=canonical.decode("utf-8"),
        document_sha256=hashlib.sha256(canonical).hexdigest(),
        created_by=original.created_by,
    )


def rejected_integrity(error: DBAPIError) -> None:
    assert getattr(error.orig, "sqlstate", None) in {"23514", "23502"}


def denied_audits(
    case: Case,
    before: dict[str, int],
    expected: int,
    *,
    action: str = "security.rejected",
    actor: UUID | None = None,
    details: dict[str, Any],
) -> None:
    after = counts(case)
    assert {table: after[table] for table in TABLES} == {table: before[table] for table in TABLES}
    assert after["audit_logs"] == before["audit_logs"] + expected
    with Session(case.database.runtime) as db:
        rows = list(
            db.scalars(
                select(AuditLog)
                .order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
                .limit(expected)
            )
        )
        assert len(rows) == expected
        assert all(
            row.action == action
            and row.outcome == "denied"
            and row.actor_id == actor
            and row.details == details
            for row in rows
        )
        assert len({row.request_id for row in rows}) == expected


@pytest.mark.parametrize("credential", ["anonymous", "source"])
def test_no_catalog_or_original_event_route_accepts_ingestion_credentials(
    case: Case, admin: Login, credential: str
) -> None:
    item, identity = seed(case, admin)
    headers = {} if credential == "anonymous" else enroll(admin).authorization
    client = case.client()
    before = counts(case)
    for path in (
        "/providers",
        "/iocs",
        f"/iocs/{item['id']}",
        f"/iocs/{item['id']}/history",
        f"/events/{identity}",
    ):
        response = client.get(BASE + path, headers=headers)
        assert response.status_code == 401 and response.json()["code"] == "unauthorized"
        assert response.headers["cache-control"] == "no-store"
    for path, body in (
        ("/lookup", {"type": "ip", "value": "192.0.2.1"}),
        ("/backfill", {"limit": 1}),
        ("/iocs", {"type": "domain", "value": "other.test", "source": "test"}),
        ("/import", {"items": [{"type": "domain", "value": "other.test", "source": "test"}]}),
    ):
        response = client.post(BASE + path, json=body, headers=headers)
        assert response.status_code == 401
    denied_audits(case, before, 9, details={"reason": "unauthorized"})


@pytest.mark.parametrize("missing", [Permission.INTELLIGENCE_READ, Permission.EVENTS_READ])
def test_frozen_event_requires_both_intelligence_and_event_read_permissions(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch, missing: Permission
) -> None:
    _, identity = seed(case, admin)
    principal = user(case, admin, "read_only")
    restricted = dict(permissions.ROLE_PERMISSIONS)
    restricted[Role.READ_ONLY] -= {missing}
    monkeypatch.setattr(permissions, "ROLE_PERMISSIONS", restricted)
    before = counts(case)
    response = principal.client.get(BASE + f"/events/{identity}", headers=principal.authorization)
    assert response.status_code == 403 and response.json()["code"] == "forbidden"
    assert "matches" not in response.json()
    if missing == Permission.INTELLIGENCE_READ:
        denied_audits(
            case,
            before,
            1,
            action="authorization.denied",
            actor=UUID(principal.user_id),
            details={"permission": missing.value},
        )
    else:
        denied_audits(case, before, 1, details={"reason": "forbidden"})


def test_runtime_can_only_append_and_read_and_narrow_publication_function_is_private(
    case: Case, admin: Login
) -> None:
    seed(case, admin)
    before = counts(case)
    with case.database.runtime.connect() as db:
        for table in TABLES:
            for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "TRIGGER"):
                allowed = db.scalar(
                    text("SELECT has_table_privilege(current_user,:table,:privilege)"),
                    {"table": table, "privilege": privilege},
                )
                assert bool(allowed) is (privilege in {"SELECT", "INSERT"})
            column = "event_id" if table == "int_event_receipts" else "id"
            for statement in (
                f"UPDATE {table} SET {column}={column}",
                f"DELETE FROM {table}",
                f"TRUNCATE {table} CASCADE",
            ):
                db.rollback()
                with pytest.raises(DBAPIError) as failure:
                    db.execute(text(statement))
                assert getattr(failure.value.orig, "sqlstate", None) == "42501"
                db.rollback()
        assert db.scalar(
            text("SELECT has_function_privilege(current_user,:name,'EXECUTE')"),
            {"name": "public.aegis_select_ioc_revision(uuid,uuid,uuid)"},
        )
    with case.database.owner.connect() as db:
        for name in (
            *(
                f"public.aegis_intelligence_{suffix}()"
                for suffix in ("immutable", "validate", "complete")
            ),
            "public.aegis_select_ioc_revision(uuid,uuid,uuid)",
        ):
            assert not db.scalar(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_proc p, LATERAL aclexplode(p.proacl) a "
                    "WHERE p.oid=CAST(:name AS regprocedure) "
                    "AND a.grantee=0 AND a.privilege_type='EXECUTE')"
                ),
                {"name": name},
            )
    assert counts(case) == before


def test_owner_triggers_block_rewrites_deletion_truncation_and_incomplete_pointer_advance(
    case: Case, admin: Login
) -> None:
    seed(case, admin)
    before = counts(case)
    assert all(before[table] > 0 for table in TABLES)
    with case.database.owner.connect() as db:
        for table in TABLES:
            column = "event_id" if table == "int_event_receipts" else "id"
            for statement in (
                f"UPDATE {table} SET {column}={column}",
                f"DELETE FROM {table}",
                f"TRUNCATE {table} CASCADE",
            ):
                with pytest.raises(DBAPIError) as failure:
                    db.execute(text(statement))
                    db.commit()
                rejected_integrity(failure.value)
                db.rollback()
        with pytest.raises(DBAPIError) as failure:
            db.execute(text("UPDATE ioc_identities SET version=version+1"))
            db.commit()
        rejected_integrity(failure.value)
        assert "IOC pointer is incomplete" in str(failure.value)
        db.rollback()
    assert counts(case) == before


def test_unpublished_identity_is_rejected_at_commit_without_partial_catalog_row(
    case: Case, admin: Login
) -> None:
    before = counts(case)
    with Session(case.database.runtime) as db:
        identity = IOCIdentity(
            kind="domain",
            canonical_value="unpublished.test",
            normalization_version=NORMALIZATION_VERSION,
            created_by=UUID(admin.user_id),
        )
        db.add(identity)
        db.flush()
        assert identity.version == 0 and identity.current_revision_id is None
        with pytest.raises(DBAPIError) as failure:
            db.commit()
        rejected_integrity(failure.value)
        assert "IOC pointer is incomplete" in str(failure.value)
        db.rollback()
    assert counts(case) == before


def test_runtime_publication_can_advance_once_with_original_previous_revision_preserved(
    case: Case, admin: Login
) -> None:
    item = create(admin)
    with Session(case.database.runtime) as db:
        original = db.get(IOCRevision, UUID(item["revision_id"]))
        assert original is not None
        frozen = deepcopy(original.document)
        revision = next_revision(original, source="second reviewed source")
        db.add(revision)
        db.flush()
        selected = db.scalar(
            text("SELECT public.aegis_select_ioc_revision(:ioc,:revision,:actor)"),
            {"ioc": revision.ioc_id, "revision": revision.id, "actor": UUID(admin.user_id)},
        )
        assert selected == 2
        selected_ioc, selected_revision = revision.ioc_id, revision.id
        db.commit()
    response = admin.client.get(BASE + f"/iocs/{item['id']}", headers=admin.authorization)
    assert response.status_code == 200 and response.json()["source"] == "second reviewed source"
    assert response.json()["version"] == 2
    with Session(case.database.runtime) as db:
        assert db.get(IOCRevision, UUID(item["revision_id"])).document == frozen
        with pytest.raises(DBAPIError) as failure:
            db.execute(
                text("SELECT public.aegis_select_ioc_revision(:ioc,:revision,:actor)"),
                {"ioc": selected_ioc, "revision": selected_revision, "actor": UUID(admin.user_id)},
            )
        rejected_integrity(failure.value)
        db.rollback()


def test_pointer_cannot_select_revision_from_another_identity(case: Case, admin: Login) -> None:
    first, second = create(admin), create(admin, "second.test")
    before = counts(case)
    with case.database.runtime.connect() as db:
        with pytest.raises(DBAPIError) as failure:
            db.execute(
                text("SELECT public.aegis_select_ioc_revision(:ioc,:revision,:actor)"),
                {
                    "ioc": UUID(first["id"]),
                    "revision": UUID(second["revision_id"]),
                    "actor": UUID(admin.user_id),
                },
            )
        rejected_integrity(failure.value)
        db.rollback()
    assert counts(case) == before


@pytest.mark.parametrize("actor_state", ["disabled", "read_only", "different_manager"])
def test_publication_function_requires_current_manager_and_exact_revision_author(
    case: Case, admin: Login, actor_state: str
) -> None:
    item = create(admin)
    actor = UUID(admin.user_id)
    if actor_state == "different_manager":
        actor = UUID(user(case, admin, "soc_manager").user_id)
    else:
        with Session(case.database.owner) as db:
            db.execute(
                update(User)
                .where(User.id == actor)
                .values(
                    **(
                        {"enabled": False}
                        if actor_state == "disabled"
                        else {"role": Role.READ_ONLY}
                    )
                )
            )
            db.commit()
    before = counts(case)
    with Session(case.database.runtime) as db:
        original = db.get(IOCRevision, UUID(item["revision_id"]))
        assert original is not None
        revision = next_revision(original)
        db.add(revision)
        db.flush()
        with pytest.raises(DBAPIError) as failure:
            db.execute(
                text("SELECT public.aegis_select_ioc_revision(:ioc,:revision,:actor)"),
                {"ioc": revision.ioc_id, "revision": revision.id, "actor": actor},
            )
        rejected_integrity(failure.value)
        db.rollback()
    assert counts(case) == before


@pytest.mark.parametrize(
    "damage",
    [
        "hash",
        "canonical",
        "ioc_id",
        "revision_id",
        "revision",
        "type",
        "value",
        "canonical_value",
        "normalization_version",
    ],
)
def test_revision_insert_rejects_forged_or_missing_original_canonical_proof(
    case: Case, admin: Login, damage: str
) -> None:
    item = create(admin)
    before = counts(case)
    with Session(case.database.runtime) as db:
        original = db.get(IOCRevision, UUID(item["revision_id"]))
        assert original is not None
        revision = next_revision(original)
        if damage == "hash":
            revision.document_sha256 = "0" * 64
        elif damage == "canonical":
            revision.canonical_document = "{}"
            revision.document_sha256 = hashlib.sha256(b"{}").hexdigest()
        else:
            revision.document.pop(damage)
            canonical = canonical_json(revision.document)
            revision.canonical_document = canonical.decode("utf-8")
            revision.document_sha256 = hashlib.sha256(canonical).hexdigest()
        db.add(revision)
        with pytest.raises(DBAPIError) as failure:
            db.flush()
        rejected_integrity(failure.value)
        db.rollback()
    assert counts(case) == before


@pytest.mark.parametrize("column", ["document", "canonical_document", "document_sha256"])
def test_sql_null_cannot_bypass_revision_proof_guard(case: Case, admin: Login, column: str) -> None:
    item = create(admin)
    before = counts(case)
    with Session(case.database.runtime) as db:
        original = db.get(IOCRevision, UUID(item["revision_id"]))
        assert original is not None
        revision = next_revision(original)
        setattr(revision, column, None)
        db.add(revision)
        with pytest.raises(DBAPIError) as failure:
            db.flush()
        rejected_integrity(failure.value)
        db.rollback()
    assert counts(case) == before


@pytest.mark.parametrize(
    "damage", ["hash", "normalization_version", "dataset", "run", "nil_dataset", "nil_run"]
)
def test_receipt_insert_rejects_foreign_hash_policy_and_replay_scope(
    case: Case, admin: Login, damage: str
) -> None:
    scope = (uuid4(), uuid4())
    _, identifiers = normalize_inputs(case, admin, [auth_event(START)], replay=scope)
    before = counts(case)
    with Session(case.database.runtime) as db:
        snapshot = db.get(NormalizedEvent, identifiers[0])
        assert snapshot is not None
        row = receipt(snapshot)
        if damage == "hash":
            row.document_sha256 = "0" * 64
        elif damage == "normalization_version":
            row.normalization_version = "future-unavailable-policy"
        elif damage in {"dataset", "nil_dataset"}:
            row.dataset_id = UUID(int=0) if damage == "nil_dataset" else uuid4()
        else:
            row.run_id = UUID(int=0) if damage == "nil_run" else uuid4()
        db.add(row)
        with pytest.raises(DBAPIError) as failure:
            db.flush()
        rejected_integrity(failure.value)
        db.rollback()
    assert counts(case) == before


@pytest.mark.parametrize("declared,insert_match", [(1, False), (0, True)])
def test_deferred_receipt_rejects_missing_or_extra_match_at_commit(
    case: Case, admin: Login, declared: int, insert_match: bool
) -> None:
    item = create(admin, "192.0.2.1", "ip")
    _, identifiers = normalize_inputs(case, admin, [auth_event(START)])
    before = counts(case)
    with Session(case.database.runtime) as db:
        snapshot = db.get(NormalizedEvent, identifiers[0])
        revision = db.get(IOCRevision, UUID(item["revision_id"]))
        assert snapshot is not None and revision is not None
        db.add(receipt(snapshot, declared))
        db.flush()
        if insert_match:
            db.add(match(snapshot, revision))
            db.flush()
        with pytest.raises(DBAPIError) as failure:
            db.commit()
        rejected_integrity(failure.value)
        assert "Intelligence receipt is incomplete" in str(failure.value)
        db.rollback()
    assert counts(case) == before


@pytest.mark.parametrize(
    "damage", ["foreign_ioc", "snapshot", "hash", "canonical", "inactive", "future"]
)
def test_match_insert_requires_original_active_revision_and_canonical_identity(
    case: Case, admin: Login, damage: str
) -> None:
    item = create(admin, "192.0.2.1", "ip", active=damage != "inactive")
    foreign = create(admin, "foreign.test") if damage == "foreign_ioc" else None
    _, identifiers = normalize_inputs(case, admin, [auth_event(START)])
    before = counts(case)
    with Session(case.database.runtime) as db:
        snapshot = db.get(NormalizedEvent, identifiers[0])
        revision = db.get(IOCRevision, UUID(item["revision_id"]))
        assert snapshot is not None and revision is not None
        evaluation = receipt(snapshot, 1)
        if damage == "future":
            evaluation.evaluated_at = revision.created_at - timedelta(seconds=1)
        db.add(evaluation)
        db.flush()
        row = match(snapshot, revision)
        if foreign is not None:
            row.ioc_id = UUID(foreign["id"])
        elif damage == "snapshot":
            row.revision_snapshot["source"] = "forged source assertion"
            row.revision_snapshot_sha256 = hashlib.sha256(
                canonical_json(row.revision_snapshot)
            ).hexdigest()
        elif damage == "hash":
            row.revision_snapshot_sha256 = "0" * 64
        elif damage == "canonical":
            row.canonical_value = "192.0.2.2"
        db.add(row)
        with pytest.raises(DBAPIError) as failure:
            db.flush()
        rejected_integrity(failure.value)
        db.rollback()
    assert counts(case) == before


@pytest.mark.parametrize("damage", ["field", "observed_value"])
def test_typed_field_and_observation_are_reverified_beyond_sql_structural_guards(
    case: Case, admin: Login, damage: str
) -> None:
    item = create(admin, "192.0.2.1", "ip")
    _, identifiers = normalize_inputs(case, admin, [auth_event(START)])
    with Session(case.database.runtime) as db:
        snapshot = db.get(NormalizedEvent, identifiers[0])
        revision = db.get(IOCRevision, UUID(item["revision_id"]))
        assert snapshot is not None and revision is not None
        row = match(snapshot, revision)
        setattr(row, damage, "host.name" if damage == "field" else "192.0.2.2")
        db.add(receipt(snapshot, 1))
        db.flush()
        db.add(row)
        db.commit()
    before = counts(case)
    response = admin.client.get(BASE + f"/events/{identifiers[0]}", headers=admin.authorization)
    assert response.status_code == 409
    assert response.json()["code"] == "intelligence_evidence_integrity_mismatch"
    assert "matches" not in response.json() and counts(case) == before
    with Session(case.database.runtime) as db:
        snapshot = db.get(NormalizedEvent, identifiers[0])
        assert snapshot is not None
        normalized = NormalizedSecurityEvent.model_validate(snapshot.document)
        with pytest.raises(ValueError, match="intelligence_match_integrity_mismatch"):
            matching.risk_contexts(db, {identifiers[0]: normalized})


def test_original_url_larger_than_canonical_limit_commits_and_reads_full_proof(
    case: Case, admin: Login
) -> None:
    canonical = "http://example.com/" + "a" * (2048 - len("http://example.com/"))
    observed = "HTTP://EXAMPLE.COM:080/" + "a" * (2048 - len("http://example.com/"))
    item = create(admin, canonical, "url", reputation="malicious", confidence=90)
    assert len(observed) == 2052 and len(item["canonical_value"]) == 2048
    _, identifiers = normalize_inputs(case, admin, [auth_event(START, http={"url": observed})])
    result = detect_once(processing_database(case), case.database.settings)
    assert result["alerts"] == 1 and result["quarantined"] == 0
    response = admin.client.get(BASE + f"/events/{identifiers[0]}", headers=admin.authorization)
    assert response.status_code == 200, response.text
    proof = response.json()
    assert proof["status"] == "evaluated" and proof["match_count"] == 1
    assert proof["matches"][0]["observed_value"] == observed
    assert proof["matches"][0]["canonical_value"] == canonical
    assert alerts(case)[0].risk_score == 45


@pytest.mark.parametrize("damage", ["raw_hash", "normalized_hash", "normalized_scope"])
def test_backfill_rechecks_original_source_and_rolls_back_prior_event_writes(
    case: Case, admin: Login, damage: str
) -> None:
    create(admin, "192.0.2.1", "ip")
    _, identifiers = normalize_inputs(
        case, admin, [auth_event(START), auth_event(START + timedelta(seconds=1))]
    )
    with Session(case.database.runtime) as db:
        ordered = list(
            db.scalars(
                select(NormalizedEvent)
                .where(NormalizedEvent.event_id.in_(identifiers))
                .order_by(NormalizedEvent.processed_at, NormalizedEvent.event_id)
            )
        )
        damaged = ordered[-1].event_id
        document = deepcopy(ordered[-1].document)
    with case.database.owner.begin() as db:
        table = "raw_events" if damage == "raw_hash" else "normalized_events"
        db.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER USER"))
        if damage == "raw_hash":
            db.execute(
                text("UPDATE raw_events SET payload_hash=:hash WHERE id=:id"),
                {"hash": "0" * 64, "id": damaged},
            )
        elif damage == "normalized_hash":
            db.execute(
                text("UPDATE normalized_events SET document_sha256=:hash WHERE event_id=:id"),
                {"hash": "0" * 64, "id": damaged},
            )
        else:
            document["run_id"] = str(uuid4())
            db.execute(
                update(NormalizedEvent)
                .where(NormalizedEvent.event_id == damaged)
                .values(
                    document=document,
                    document_sha256=hashlib.sha256(canonical_json(document)).hexdigest(),
                )
            )
        db.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER USER"))
    before = counts(case)
    response = backfill(admin)
    assert (
        response.status_code == 409
        and response.json()["code"] == "intelligence_evidence_integrity_mismatch"
    )
    assert counts(case) == before and not alerts(case)


@pytest.mark.parametrize("operation", ["create", "backfill"])
@pytest.mark.parametrize("change", ["role", "disabled", "revoked"])
def test_mutation_rechecks_current_authority_after_waiting_for_shared_lock(
    case: Case, admin: Login, operation: str, change: str
) -> None:
    _, _ = normalize_inputs(case, admin, [auth_event(START)])
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

    def mutate() -> Any:
        if operation == "backfill":
            return backfill(operator)
        return operator.client.post(
            BASE + "/iocs",
            json={"type": "domain", "value": "new.test", "source": "test"},
            headers=operator.authorization,
        )

    event.listen(engine, "before_cursor_execute", observe)
    try:
        with case.database.owner.connect() as blocker:
            blocker.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": ADMIN_LOCK_ID})
            with ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(mutate)
                try:
                    assert reached.wait(timeout=3), "Mutation did not reach shared authority lock"
                    with Session(case.database.owner) as db:
                        identifier = UUID(operator.user_id)
                        if change == "revoked":
                            db.execute(
                                update(AuthSession)
                                .where(AuthSession.user_id == identifier)
                                .values(revoked_at=utcnow())
                            )
                        else:
                            db.execute(
                                update(User)
                                .where(User.id == identifier)
                                .values(
                                    **(
                                        {"role": Role.READ_ONLY}
                                        if change == "role"
                                        else {"enabled": False}
                                    )
                                )
                            )
                        db.commit()
                finally:
                    blocker.rollback()
                response = pending.result(timeout=10)
    finally:
        event.remove(engine, "before_cursor_execute", observe)
    assert response.status_code == 403 and response.json()["code"] == "forbidden", response.text
    denied_audits(case, before, 1, details={"reason": "forbidden"})


def test_concurrent_patches_recheck_fresh_version_after_shared_publication_lock(
    case: Case, admin: Login
) -> None:
    item = create(admin)
    principals = [user(case, admin, "soc_manager") for _ in range(2)]
    before = counts(case)

    def patch(principal: Login, source: str) -> Any:
        return principal.client.patch(
            BASE + f"/iocs/{item['id']}",
            json={"source": source},
            headers={**principal.authorization, "If-Match": '"1"'},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        pending = [
            executor.submit(patch, principal, f"reviewed source {index}")
            for index, principal in enumerate(principals)
        ]
        responses = [request.result(timeout=10) for request in pending]
    assert sorted(response.status_code for response in responses) == [200, 412]
    changed = next(response.json() for response in responses if response.status_code == 200)
    rejected = next(response for response in responses if response.status_code == 412)
    assert rejected.json()["code"] == "version_conflict"
    assert changed["version"] == changed["revision"] == 2
    assert counts(case)["ioc_revisions"] == before["ioc_revisions"] + 1
    response = admin.client.get(BASE + f"/iocs/{item['id']}", headers=admin.authorization)
    assert response.status_code == 200 and response.json() == changed


@pytest.mark.parametrize("operation", ["create", "backfill"])
def test_audit_failure_rolls_back_published_pointer_and_all_local_match_writes(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    if operation == "backfill":
        create(admin, "192.0.2.1", "ip")
        normalize_inputs(case, admin, [auth_event(START)])
    before = counts(case)
    reached: list[dict[str, int]] = []

    def fail(db: Session, **values: Any) -> None:
        reached.append(
            {
                model.__tablename__: int(db.scalar(select(func.count()).select_from(model)) or 0)
                for model in (IOCIdentity, IOCRevision, IntEventReceipt, IntEventMatch)
            }
        )
        raise RuntimeError("test-only local audit failure")

    with monkeypatch.context() as isolated:
        path = (
            "app.modules.intelligence.matching.append_audit"
            if operation == "backfill"
            else "app.modules.intelligence.service.append_audit"
        )
        isolated.setattr(path, fail)
        response = (
            backfill(admin)
            if operation == "backfill"
            else admin.client.post(
                BASE + "/iocs",
                json={"type": "domain", "value": "new.test", "source": "test"},
                headers=admin.authorization,
            )
        )
    assert response.status_code == 500 and response.json()["code"] == "internal_error"
    assert len(reached) == 1
    affected = TABLES[2:] if operation == "backfill" else TABLES[:2]
    assert all(reached[0][table] > before[table] for table in affected)
    assert counts(case) == before and not alerts(case)


def test_backfill_event_budget_and_strict_http_limits_leave_unprocessed_receipts_pending(
    case: Case, admin: Login
) -> None:
    create(admin, "192.0.2.1", "ip")
    normalize_inputs(case, admin, [auth_event(START + timedelta(seconds=i)) for i in range(3)])
    before = counts(case)
    for limit in (0, 101, True, "1", None):
        response = admin.client.post(
            BASE + "/backfill", json={"limit": limit}, headers=admin.authorization
        )
        assert response.status_code == 422 and counts(case) == before
    first = backfill(admin, 1)
    assert first.status_code == 200, first.text
    assert first.json()["events"] == first.json()["matches"] == 1
    assert first.json()["remaining"] == 2 and first.json()["alerts_created"] == 0
    assert counts(case)["int_event_receipts"] == counts(case)["int_event_matches"] == 1
    second = backfill(admin, 1)
    assert second.status_code == 200 and second.json()["remaining"] == 1
    assert counts(case)["int_event_receipts"] == counts(case)["int_event_matches"] == 2
    assert not alerts(case)


def test_risk_reads_at_most_one_hundred_strongest_verified_matches_without_losing_maximum(
    case: Case, admin: Login
) -> None:
    create(admin, "192.0.2.1", "ip", reputation="suspicious", confidence=50)
    strong = create(admin, "192.0.2.2", "ip", reputation="malicious", confidence=90)
    events = [auth_event(START + timedelta(seconds=i)) for i in range(100)]
    events.append(auth_event(START + timedelta(seconds=100), source={"ip": "192.0.2.2"}))
    _, identifiers = normalize_inputs(case, admin, events)
    assert backfill(admin, 100).json()["remaining"] == 1
    assert backfill(admin, 100).json()["remaining"] == 0
    before = counts(case)
    with Session(case.database.runtime) as db:
        documents = {
            row.event_id: NormalizedSecurityEvent.model_validate(row.document)
            for row in db.scalars(
                select(NormalizedEvent).where(NormalizedEvent.event_id.in_(identifiers))
            )
        }
        facts, metadata = matching.risk_contexts(db, documents)
    assert metadata == {
        "selected_matches": 100,
        "available_matches": 101,
        "truncated": True,
        "selection": "highest-i-points-then-revision-event-field",
        "maximum": 100,
    }
    assert len(facts) == 100 and sum(fact.value == "malicious" for fact in facts) == 1
    assert facts[0].provenance.source == "local-ioc-revision:" + strong["revision_id"]
    assert facts[0].confidence == 90
    assert counts(case) == before and not alerts(case)
