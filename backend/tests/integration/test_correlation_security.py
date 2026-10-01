"""Independent real-database checks for temporal-rule authority and evidence."""

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

from app.core.permissions import Role
from app.infrastructure.database import ADMIN_LOCK_ID, utcnow
from app.modules.alerts.models import Alert
from app.modules.audit.models import AuditLog
from app.modules.auth.models import AuthSession
from app.modules.correlation.models import CorrelationJob, CorrelationScope
from app.modules.incidents.models import Incident, IncidentAlert, IncidentTimeline
from app.modules.ingestion.models import IngestionSource
from app.modules.ingestion.processing import process_event
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.models import NormalizedEvent
from app.modules.normalization.processing import process_once as normalize_once
from app.modules.users.models import User

from .helper_ingestion import accept, enroll, processing_database, status
from .helpers import Case, Login
from .test_initial_alerts import normalize_events, user

pytestmark = pytest.mark.integration


def trace_documents(case: Case, admin: Login, facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    start = utcnow() - timedelta(seconds=60)
    ids = normalize_events(
        case,
        admin,
        [
            {
                "source_type": "generic_json",
                "timestamp": (start + timedelta(seconds=index)).isoformat(),
                "raw_event": {
                    "host": {"id": "registered-host-17", "name": "host17", "os": "linux"},
                    "user": {"name": "alice", "realm": "LAB"},
                    "source": {"ip": "192.0.2.10"},
                    **fact,
                },
            }
            for index, fact in enumerate(facts)
        ],
    )
    with Session(case.database.runtime) as session:
        rows = [session.get(NormalizedEvent, event_id) for event_id in ids]
        assert all(row is not None for row in rows)
        return [deepcopy(row.document) for row in rows if row is not None]


def authentication_trace(case: Case, admin: Login) -> list[dict[str, Any]]:
    return trace_documents(
        case,
        admin,
        [
            {"event": {"category": "authentication", "outcome": outcome}}
            for outcome in ["failure"] * 5 + ["success"]
        ],
    )


def pure_test(principal: Login, rule_id: str, documents: list[dict[str, Any]]) -> Any:
    response = principal.client.post(
        "/api/v1/correlations/test",
        json={"id": rule_id, "events": documents},
        headers=principal.authorization,
    )
    assert response.status_code == 200, response.text
    return response.json()


def domain_counts(case: Case) -> dict[str, int]:
    with Session(case.database.runtime) as session:
        return {
            model.__tablename__: int(session.scalar(select(func.count()).select_from(model)) or 0)
            for model in (
                Alert,
                CorrelationJob,
                CorrelationScope,
                Incident,
                IncidentAlert,
                IncidentTimeline,
            )
        }


def correlated_alert(case: Case, admin: Login) -> Alert:
    from app.modules.correlation.processing import process_once

    authentication_trace(case, admin)
    process_once(
        processing_database(case), case.database.settings, now=utcnow() + timedelta(seconds=121)
    )
    with Session(case.database.runtime, expire_on_commit=False) as session:
        record = session.scalar(
            select(Alert).where(Alert.rule_id == "possible_bruteforce_compromise")
        )
        assert record is not None and record.event_count == 6
        return record


def empty_incident(admin: Login) -> dict[str, Any]:
    response = admin.client.post(
        "/api/v1/incidents",
        json={"title": "Independent correlation evidence integrity check"},
        headers={**admin.authorization, "Idempotency-Key": uuid4().hex},
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


def replay_authentication_trace(case: Case, admin: Login) -> tuple[UUID, UUID, list[UUID]]:
    source = enroll(admin)
    dataset_id, run_id = uuid4(), uuid4()
    with Session(case.database.owner) as session:
        session.execute(
            update(IngestionSource)
            .where(IngestionSource.id == UUID(source.id))
            .values(mode="replay", dataset_id=dataset_id, run_id=run_id)
        )
        session.commit()
    start = utcnow() - timedelta(days=1)
    receipt = accept(
        admin.client,
        source,
        {
            "events": [
                {
                    "source_type": "generic_json",
                    "source_event_id": f"replay-review-{index}",
                    "timestamp": (start + timedelta(seconds=index)).isoformat(),
                    "raw_event": {
                        "host": {"id": "registered-host-17", "name": "host17"},
                        "user": {"name": "alice", "realm": "LAB"},
                        "source": {"ip": "192.0.2.10"},
                        "event": {"category": "authentication", "outcome": outcome},
                    },
                }
                for index, outcome in enumerate(["failure"] * 5 + ["success"])
            ]
        },
    )
    ids = [UUID(row["event_id"]) for row in status(admin.client, source, receipt)["records"]]
    database = processing_database(case)
    for event_id in ids:
        assert process_event(database, case.database.settings, event_id, 1) == "staged"
    projected: list[dict[str, Any]] = []
    normalize_once(database, case.database.settings, projected.append)
    assert {UUID(document["event_id"]) for document in projected} == set(ids)
    return dataset_id, run_id, ids


def temporal_rule(principal: Login) -> dict[str, Any]:
    response = principal.client.get("/api/v1/correlations", headers=principal.authorization)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    rules = response.json()["items"]
    assert rules
    return dict(rules[0])


def patch_rule(principal: Login, rule: dict[str, Any], **changes: Any) -> Any:
    return principal.client.patch(
        f"/api/v1/correlations/{rule['id']}",
        json=changes,
        headers={**principal.authorization, "If-Match": f'"{rule["version"]}"'},
    )


def deployment_audits(case: Case) -> int:
    with Session(case.database.runtime) as session:
        return int(
            session.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(AuditLog.action == "correlation.deployment_changed")
            )
            or 0
        )


@pytest.mark.parametrize("change", ["role", "disabled", "revoked", "absolute", "idle"])
def test_temporal_deployment_rechecks_authority_after_waiting_for_lock(
    case: Case, admin: Login, change: str
) -> None:
    manager = user(case, admin, "soc_manager")
    rule = temporal_rule(manager)
    before = deployment_audits(case)
    reached_lock = Event()
    engine = manager.client.app.state.database.engine

    def observe_lock(
        connection: Any,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        if "pg_advisory_xact_lock" in statement:
            reached_lock.set()

    event.listen(engine, "before_cursor_execute", observe_lock)
    try:
        with case.database.owner.connect() as blocker:
            blocker.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": ADMIN_LOCK_ID})
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(patch_rule, manager, rule, enabled=not rule["enabled"])
                try:
                    assert reached_lock.wait(timeout=3), "Mutation did not reach authority lock"
                    # The request authenticated before the lock. Only this test's
                    # fresh database changes while the real route waits.
                    with Session(case.database.owner) as session:
                        user_id = UUID(manager.user_id)
                        now = utcnow()
                        if change == "role":
                            session.execute(
                                update(User).where(User.id == user_id).values(role=Role.READ_ONLY)
                            )
                        elif change == "disabled":
                            session.execute(
                                update(User).where(User.id == user_id).values(enabled=False)
                            )
                        else:
                            changes = {
                                "revoked": {"revoked_at": now},
                                "absolute": {"absolute_expires_at": now - timedelta(seconds=1)},
                                "idle": {
                                    "last_seen_at": now
                                    - timedelta(
                                        seconds=case.database.settings.session_idle_seconds + 10
                                    )
                                },
                            }
                            session.execute(
                                update(AuthSession)
                                .where(AuthSession.user_id == user_id)
                                .values(**changes[change])
                            )
                        session.commit()
                finally:
                    blocker.rollback()
                response = future.result(timeout=10)
    finally:
        event.remove(engine, "before_cursor_execute", observe_lock)
    assert response.status_code == 403, response.text
    current = admin.client.get(f"/api/v1/correlations/{rule['id']}", headers=admin.authorization)
    assert current.status_code == 200
    assert current.json()["version"] == rule["version"]
    assert current.json()["enabled"] == rule["enabled"]
    assert deployment_audits(case) == before


def test_failed_temporal_deployment_audit_rolls_back_configuration(
    case: Case, admin: Login
) -> None:
    rule = temporal_rule(admin)
    before = deployment_audits(case)
    with case.database.owner.begin() as connection:
        connection.execute(text("REVOKE INSERT ON audit_logs FROM aegis_app"))
    try:
        response = patch_rule(admin, rule, enabled=not rule["enabled"])
        assert response.status_code == 503, response.text
    finally:
        with case.database.owner.begin() as connection:
            connection.execute(text("GRANT INSERT ON audit_logs TO aegis_app"))
    current = admin.client.get(f"/api/v1/correlations/{rule['id']}", headers=admin.authorization)
    assert current.status_code == 200
    assert current.json()["version"] == rule["version"]
    assert current.json()["enabled"] == rule["enabled"]
    assert deployment_audits(case) == before


@pytest.mark.parametrize(
    "identity_conflict", ["missing_realm", "delimiter", "id_vs_name", "id_case", "name_case"]
)
def test_temporal_identity_keys_do_not_join_ambiguous_or_colliding_accounts(
    case: Case, admin: Login, identity_conflict: str
) -> None:
    documents = authentication_trace(case, admin)
    assert len(pure_test(admin, "possible_bruteforce_compromise", documents)["matches"]) == 1
    for document in documents:
        account = document["user"]
        if identity_conflict == "missing_realm":
            account["realm"] = None
        elif identity_conflict == "delimiter":
            account.update({"realm": "x:account:y", "name": "z"})
        elif identity_conflict == "id_vs_name":
            account.update({"id": "alice", "name": "original-account"})
        elif identity_conflict == "id_case":
            account["id"] = "Opaque-Account-ID"
        elif identity_conflict == "name_case":
            account["name"] = "Alice"
    if identity_conflict == "delimiter":
        documents[-1]["user"].update({"realm": "x", "name": "y:account:z"})
    elif identity_conflict == "id_vs_name":
        documents[-1]["user"].update({"id": None, "name": "alice"})
    elif identity_conflict == "id_case":
        documents[-1]["user"]["id"] = "opaque-account-id"
    elif identity_conflict == "name_case":
        documents[-1]["user"]["name"] = "alice"
    result = pure_test(admin, "possible_bruteforce_compromise", documents)
    assert result["complete"] is True
    assert result["matches"] == []


def test_known_session_conflict_prevents_login_privilege_sequence(case: Case, admin: Login) -> None:
    documents = trace_documents(
        case,
        admin,
        [
            {"event": {"category": "authentication", "outcome": "success"}},
            {
                "event": {"category": "iam", "code": "4732"},
                "extensions": {"group": {"id": "S-1-5-32-544"}},
            },
        ],
    )
    for document in documents:
        document["session"] = {
            "id": "session-a",
            "provider": "windows-security",
            "host_id": "registered-host-17",
            "boot_id": "boot-1",
        }
    assert len(pure_test(admin, "login_then_local_admin_change", documents)["matches"]) == 1
    documents[-1]["session"]["id"] = "session-b"
    assert pure_test(admin, "login_then_local_admin_change", documents)["matches"] == []


def test_multi_stage_chain_requires_same_process_for_outbound_connection(
    case: Case, admin: Login
) -> None:
    facts: list[dict[str, Any]] = [
        {"event": {"category": "authentication", "outcome": outcome}}
        for outcome in ["failure"] * 5 + ["success"]
    ]
    facts.extend(
        [
            {
                "event": {"category": "process", "type": "process_start"},
                "process": {"name": "powershell.exe", "entity_id": "process-1"},
            },
            {
                "event": {"category": "iam", "code": "4732"},
                "extensions": {"group": {"id": "S-1-5-32-544"}},
            },
            {
                "event": {"category": "network", "action": "outbound_connection"},
                "process": {"name": "powershell.exe", "entity_id": "process-1"},
            },
        ]
    )
    documents = trace_documents(case, admin, facts)
    for document in documents[5:]:
        document["session"] = {
            "id": "session-a",
            "provider": "windows-security",
            "host_id": "registered-host-17",
            "boot_id": "boot-1",
        }
    assert len(pure_test(admin, "possible_multi_stage_compromise", documents)["matches"]) == 1
    documents[-1]["process"] = {**documents[-1]["process"], "entity_id": "process-2"}
    assert pure_test(admin, "possible_multi_stage_compromise", documents)["matches"] == []


def test_actual_windows_group_change_parser_preserves_actor_and_target(
    case: Case, admin: Login
) -> None:
    start = utcnow() - timedelta(seconds=60)
    actor_sid = "S-1-5-21-1-1001"
    member_sid = "S-1-5-21-1-1002"
    ids = normalize_events(
        case,
        admin,
        [
            {
                "source_type": "windows_auth",
                "timestamp": start.isoformat(),
                "raw_event": {
                    "EventID": 4624,
                    "Computer": "windows-host17",
                    "host_id": "registered-host-17",
                    "EventData": {
                        "SubjectUserName": "SYSTEM",
                        "SubjectDomainName": "NT AUTHORITY",
                        "SubjectUserSid": "S-1-5-18",
                        "TargetUserName": "alice",
                        "TargetDomainName": "LAB",
                        "TargetUserSid": actor_sid,
                        "TargetLogonId": "0x17",
                    },
                },
            },
            {
                "source_type": "windows_auth",
                "timestamp": (start + timedelta(seconds=1)).isoformat(),
                "raw_event": {
                    "EventID": 4732,
                    "Computer": "windows-host17",
                    "host_id": "registered-host-17",
                    "EventData": {
                        "SubjectUserName": "alice",
                        "SubjectDomainName": "LAB",
                        "SubjectUserSid": actor_sid,
                        "SubjectLogonId": "0x17",
                        "MemberSid": member_sid,
                        "MemberName": "bob",
                        "TargetSid": "S-1-5-32-544",
                        "TargetUserName": "Administrators",
                    },
                },
            },
        ],
    )
    with Session(case.database.runtime) as session:
        rows = [session.get(NormalizedEvent, event_id) for event_id in ids]
        assert all(row is not None for row in rows)
        documents = [deepcopy(row.document) for row in rows if row is not None]
    assert documents[-1]["user"]["id"] == actor_sid
    assert documents[-1]["user"]["name"] == "alice"
    assert documents[-1]["user"]["target"]["id"] == member_sid
    assert documents[-1]["extensions"]["group"]["id"] == "S-1-5-32-544"
    result = pure_test(admin, "login_then_local_admin_change", documents)
    assert len(result["matches"]) == 1
    assert set(result["matches"][0]["event_ids"]) == {str(event_id) for event_id in ids}
    # The added member is a distinct account. Replacing the actor with that
    # target cannot turn their privileges into an action of the logged-in actor.
    documents[-1]["user"]["id"] = member_sid
    documents[-1]["user"]["name"] = "bob"
    assert pure_test(admin, "login_then_local_admin_change", documents)["matches"] == []


def test_actual_windows_authentication_uses_target_account_instead_of_system_actor(
    case: Case, admin: Login
) -> None:
    start = utcnow() - timedelta(seconds=60)
    ids = normalize_events(
        case,
        admin,
        [
            {
                "source_type": "windows_auth",
                "timestamp": (start + timedelta(seconds=index)).isoformat(),
                "raw_event": {
                    "EventID": 4625 if index < 5 else 4624,
                    "Computer": "windows-host17",
                    "host_id": "registered-host-17",
                    "EventData": {
                        "SubjectUserName": "SYSTEM",
                        "SubjectDomainName": "NT AUTHORITY",
                        "SubjectUserSid": "S-1-5-18",
                        "TargetUserName": "alice",
                        "TargetDomainName": "LAB",
                        "TargetUserSid": "S-1-5-21-1-1001",
                        "IpAddress": "192.0.2.10",
                    },
                },
            }
            for index in range(6)
        ],
    )
    with Session(case.database.runtime) as session:
        rows = [session.get(NormalizedEvent, event_id) for event_id in ids]
        assert all(row is not None for row in rows)
        documents = [deepcopy(row.document) for row in rows if row is not None]
    assert all(document["user"]["id"] == "S-1-5-18" for document in documents)
    assert all(document["user"]["target"]["name"] == "alice" for document in documents)
    assert len(pure_test(admin, "possible_bruteforce_compromise", documents)["matches"]) == 1
    # Real failed logons often do not resolve the target SID. The named domain
    # account remains joinable, but a shared unknown SID cannot identify Bob.
    for document in documents[:-1]:
        document["user"]["target"]["id"] = "S-1-0-0"
    assert len(pure_test(admin, "possible_bruteforce_compromise", documents)["matches"]) == 1
    documents[-1]["user"]["target"].update({"id": "S-1-0-0", "name": "bob"})
    assert pure_test(admin, "possible_bruteforce_compromise", documents)["matches"] == []
    for document in documents:
        document["user"]["target"].update({"id": "S-1-5-21-1-1001", "name": "alice"})
    documents[-1]["user"]["target"]["id"] = "S-1-5-21-1-1002"
    assert pure_test(admin, "possible_bruteforce_compromise", documents)["matches"] == []
    documents[-1]["user"]["target"].update({"id": "S-1-5-21-1-1002", "name": "bob"})
    assert pure_test(admin, "possible_bruteforce_compromise", documents)["matches"] == []
    for document in documents:
        document["user"]["target"] = {"id": None, "name": None, "realm": None}
    assert pure_test(admin, "possible_bruteforce_compromise", documents)["matches"] == []
    for document in documents[:-1]:
        document["user"]["target"] = {"id": "S-1-5-21-1-1001", "name": "alice", "realm": "LAB"}
    assert len(pure_test(admin, "repeated_authentication_failures", documents[:-1])["matches"]) == 1
    for document in documents[3:5]:
        document["user"]["target"]["id"] = "S-1-5-21-1-1002"
    assert pure_test(admin, "repeated_authentication_failures", documents[:-1])["matches"] == []


def test_valid_prior_session_is_not_hidden_by_later_unrelated_logon(
    case: Case, admin: Login
) -> None:
    documents = trace_documents(
        case,
        admin,
        [
            {"event": {"category": "authentication", "outcome": "success"}},
            {"event": {"category": "authentication", "outcome": "success"}},
            {
                "event": {"category": "iam", "code": "4732"},
                "extensions": {"group": {"id": "S-1-5-32-544"}},
            },
        ],
    )
    for document, identity in zip(documents, ["session-a", "session-b", "session-a"], strict=True):
        document["session"] = {
            "id": identity,
            "provider": "windows-security",
            "host_id": "registered-host-17",
            "boot_id": "boot-1",
        }
    matches = pure_test(admin, "login_then_local_admin_change", documents)["matches"]
    assert len(matches) == 1
    assert matches[0]["event_ids"] == [documents[0]["event_id"], documents[-1]["event_id"]]


def test_pure_temporal_test_has_no_domain_effects_even_when_rule_is_disabled(
    case: Case, admin: Login
) -> None:
    documents = authentication_trace(case, admin)
    rule = temporal_rule(admin)
    assert rule["id"] == "possible_bruteforce_compromise"
    disabled = patch_rule(admin, rule, enabled=False)
    assert disabled.status_code == 200, disabled.text
    analyst = user(case, admin, "soc_analyst")
    before = domain_counts(case)
    result = pure_test(analyst, rule["id"], documents)
    assert result["complete"] is True and len(result["matches"]) == 1
    assert domain_counts(case) == before


def test_duplicate_ids_are_rejected_in_pure_temporal_test(case: Case, admin: Login) -> None:
    documents = authentication_trace(case, admin)
    before = domain_counts(case)
    response = admin.client.post(
        "/api/v1/correlations/test",
        json={
            "id": "possible_bruteforce_compromise",
            "events": [documents[0]] * 5 + [documents[-1]],
        },
        headers=admin.authorization,
    )
    assert response.status_code == 422, response.text
    assert domain_counts(case) == before


def test_viewer_and_collector_cannot_test_publish_or_seal_temporal_rules(
    case: Case, admin: Login
) -> None:
    documents = authentication_trace(case, admin)
    reader = user(case, admin, "read_only")
    source = enroll(admin)
    rule = temporal_rule(reader)
    before = domain_counts(case)
    for authorization, expected in [(reader.authorization, 403), (source.authorization, 401)]:
        tests = [
            (
                "/api/v1/correlations/test",
                {"id": rule["id"], "events": documents},
            ),
            (
                "/api/v1/correlations/replay/finalize",
                {
                    "dataset_id": documents[0]["dataset_id"],
                    "run_id": "00000000-0000-0000-0000-000000000001",
                    "expected_event_count": 1,
                },
            ),
        ]
        for path, body in tests:
            response = admin.client.post(path, json=body, headers=authorization)
            assert response.status_code == expected, response.text
        response = admin.client.patch(
            f"/api/v1/correlations/{rule['id']}",
            json={"enabled": not rule["enabled"]},
            headers={**authorization, "If-Match": f'"{rule["version"]}"'},
        )
        assert response.status_code == expected, response.text
    assert domain_counts(case) == before


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE alerts SET event_snapshots='[]'::jsonb WHERE id=:id",
        "UPDATE alerts SET event_snapshot='{}'::jsonb WHERE id=:id",
        "UPDATE alerts SET reason='{}'::jsonb WHERE id=:id",
        "DELETE FROM alerts WHERE id=:id",
    ],
)
def test_runtime_cannot_rewrite_or_remove_correlation_evidence(
    case: Case, admin: Login, statement: str
) -> None:
    record = correlated_alert(case, admin)
    before = domain_counts(case)
    with Session(case.database.runtime) as session:
        with pytest.raises(DBAPIError) as denied:
            session.execute(text(statement), {"id": record.id})
        assert getattr(denied.value.orig, "sqlstate", None) == "42501"
        session.rollback()
    with Session(case.database.runtime) as session:
        preserved = session.get(Alert, record.id)
        assert preserved is not None
        assert preserved.event_snapshots == record.event_snapshots
        assert preserved.event_snapshot == record.event_snapshot
    assert domain_counts(case) == before


@pytest.mark.parametrize(
    "corruption", ["hash", "duplicate", "missing_anchor", "anchor_mismatch", "scope", "empty"]
)
def test_corrupted_contributor_sets_cannot_be_attached_to_incident(
    case: Case, admin: Login, corruption: str
) -> None:
    record = correlated_alert(case, admin)
    incident = empty_incident(admin)
    proof = deepcopy(record.event_snapshots)
    extra = trace_documents(case, admin, [{"event": {"category": "network"}}])[0]
    with Session(case.database.owner) as session:
        if corruption == "hash":
            proof[0]["event_snapshot"]["event"]["action"] = "altered-without-valid-hash"
        elif corruption == "duplicate":
            proof[0] = deepcopy(proof[1])
        elif corruption == "missing_anchor":
            proof[-1] = {
                "event_id": extra["event_id"],
                "event_snapshot": extra,
                "event_sha256": hashlib.sha256(canonical_json(extra)).hexdigest(),
            }
        elif corruption == "anchor_mismatch":
            anchor = deepcopy(record.event_snapshot)
            anchor["source"]["name"] = "changed-anchor-only"
            session.execute(
                update(Alert)
                .where(Alert.id == record.id)
                .values(
                    event_snapshot=anchor,
                    event_sha256=hashlib.sha256(canonical_json(anchor)).hexdigest(),
                )
            )
        elif corruption == "empty":
            proof = []
        else:
            proof[0]["event_snapshot"]["mode"] = "replay"
            proof[0]["event_snapshot"]["run_id"] = str(uuid4())
            proof[0]["event_sha256"] = hashlib.sha256(
                canonical_json(proof[0]["event_snapshot"])
            ).hexdigest()
        session.execute(update(Alert).where(Alert.id == record.id).values(event_snapshots=proof))
        session.commit()
    before = domain_counts(case)
    response = admin.client.post(
        f"/api/v1/incidents/{incident['id']}/alerts",
        json={"alert_id": str(record.id)},
        headers={**admin.authorization, "If-Match": f'"{incident["version"]}"'},
    )
    assert response.status_code == 409, response.text
    assert domain_counts(case) == before
    detail = admin.client.get(f"/api/v1/incidents/{incident['id']}", headers=admin.authorization)
    assert detail.status_code == 200
    assert detail.json()["version"] == incident["version"]
    assert detail.json()["related_alerts"] == []


def test_failed_automatic_case_audit_rolls_back_correlation_anchor_then_retry_recovers(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.modules.correlation.processing import process_once
    from app.modules.incidents import service

    documents = authentication_trace(case, admin)
    catalog = admin.client.get("/api/v1/correlations", headers=admin.authorization)
    assert catalog.status_code == 200
    for rule in catalog.json()["items"]:
        if rule["id"] != "possible_bruteforce_compromise":
            assert patch_rule(admin, rule, enabled=False).status_code == 200
    database = processing_database(case)
    now = utcnow() + timedelta(seconds=121)
    append_real_audit = service.append_audit

    def fail_case_creation(session: Session, **kwargs: Any) -> AuditLog:
        if kwargs.get("action") == "incident.created":
            raise RuntimeError("planned-correlation-case-audit-failure")
        return append_real_audit(session, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(service, "append_audit", fail_case_creation)
        with pytest.raises(RuntimeError, match="planned-correlation-case-audit-failure"):
            process_once(database, case.database.settings, now=now)
    with Session(case.database.runtime) as session:
        job = session.get(CorrelationJob, UUID(documents[-1]["event_id"]))
        assert job is not None and job.state == "pending" and job.processed_at is None
        assert session.scalar(select(Alert)) is None
        assert session.scalar(select(Incident)) is None
        assert session.scalar(select(AuditLog).where(AuditLog.action == "alert.created")) is None
    assert process_once(database, case.database.settings, now=now)["alerts"] == 1
    recovered = domain_counts(case)
    assert recovered["alerts"] == 1 and recovered["incidents"] == 1
    assert process_once(processing_database(case), case.database.settings, now=now)["alerts"] == 0
    assert domain_counts(case) == recovered


def test_sealed_replay_keeps_deployment_decision_when_live_configuration_changes(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.modules.correlation import processing
    from app.modules.correlation.processing import process_once
    from app.modules.detections.processing import RuleConfigurationError

    dataset_id, run_id, ids = replay_authentication_trace(case, admin)
    database = processing_database(case)
    assert process_once(database, case.database.settings)["processed"] == 0
    rule = temporal_rule(admin)
    assert rule["id"] == "possible_bruteforce_compromise" and rule["enabled"] is True
    sealed = admin.client.post(
        "/api/v1/correlations/replay/finalize",
        json={
            "dataset_id": str(dataset_id),
            "run_id": str(run_id),
            "expected_event_count": 6,
        },
        headers=admin.authorization,
    )
    assert sealed.status_code == 200, sealed.text
    assert sealed.json()["event_count"] == 6 and sealed.json()["manifest_sha256"]
    with monkeypatch.context() as patch:
        patch.setattr(processing, "EVALUATOR_VERSION", "correlation-unavailable-test-version")
        with pytest.raises(RuleConfigurationError):
            process_once(database, case.database.settings)
    with Session(case.database.runtime) as session:
        checkpoint = session.get(CorrelationJob, ids[-1])
        assert checkpoint is not None and checkpoint.state == "pending"
        assert session.scalar(select(Alert)) is None
    disabled = patch_rule(admin, rule, enabled=False)
    assert disabled.status_code == 200 and disabled.json()["version"] == rule["version"] + 1
    process_once(database, case.database.settings)
    with Session(case.database.runtime) as session:
        record = session.scalar(
            select(Alert).where(
                Alert.rule_id == rule["id"], Alert.mode == "replay", Alert.run_id == run_id
            )
        )
        assert record is not None and record.event_count == 6
        assert record.rule_snapshot["deployment_version"] == rule["version"]
        checkpoint = session.get(CorrelationJob, ids[-1])
        assert checkpoint is not None and checkpoint.state == "processed"
        evaluation = next(item for item in checkpoint.evaluated_rules if item["id"] == rule["id"])
        assert evaluation["enabled"] is True
        assert evaluation["deployment_version"] == rule["version"]
    recovered = domain_counts(case)
    process_once(processing_database(case), case.database.settings)
    assert domain_counts(case) == recovered
