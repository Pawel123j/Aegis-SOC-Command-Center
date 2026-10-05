"""Independent adversarial checks for trusted risk inputs and historical assessments."""

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

from app.core.permissions import Role
from app.infrastructure.database import ADMIN_LOCK_ID, utcnow
from app.modules.alerts.models import Alert
from app.modules.audit.models import AuditLog
from app.modules.auth.models import AuthSession
from app.modules.incidents.models import Incident, IncidentTimeline
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.models import NormalizedEvent
from app.modules.risk import engine, engine_v4
from app.modules.risk.schemas import RiskInput
from app.modules.users.models import User

from .helper_ingestion import enroll, processing_database
from .helpers import Case, Login
from .test_correlation_security import correlated_alert, trace_documents
from .test_initial_alerts import alerts, detect_once, normalize_events, powershell, user

pytestmark = pytest.mark.integration


def seed_signals(case: Case, admin: Login, count: int = 1) -> list[Alert]:
    normalize_events(case, admin, [powershell() for _ in range(count)])
    detect_once(processing_database(case), case.database.settings)
    records = alerts(case)
    assert len(records) == count
    return records


def make_case(admin: Login, records: list[Alert]) -> dict[str, Any]:
    response = admin.client.post(
        "/api/v1/incidents",
        json={
            "title": "Independent risk security review",
            "alert_ids": [str(r.id) for r in records],
        },
        headers={**admin.authorization, "Idempotency-Key": uuid4().hex},
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


def risk_counts(case: Case) -> dict[str, int]:
    with Session(case.database.runtime) as session:
        values = {
            model.__tablename__: int(session.scalar(select(func.count()).select_from(model)) or 0)
            for model in (Alert, Incident, IncidentTimeline)
        }
        values["risk_calculations"] = int(
            session.scalar(text("SELECT count(*) FROM risk_calculations")) or 0
        )
        values["risk_audit"] = int(
            session.scalar(
                select(func.count()).select_from(AuditLog).where(AuditLog.action.like("risk.%"))
            )
            or 0
        )
        return values


def backfill(principal: Login, limit: int = 100) -> Any:
    return principal.client.post(
        "/api/v1/risk/backfill", json={"limit": limit}, headers=principal.authorization
    )


def current_case(admin: Login, identifier: str) -> dict[str, Any]:
    response = admin.client.get(f"/api/v1/incidents/{identifier}", headers=admin.authorization)
    assert response.status_code == 200, response.text
    return dict(response.json())


def legacy_projection(case: Case, record: Alert) -> None:
    """Simulate a pre-risk alert in this test's fresh, exclusively owned database."""
    with Session(case.database.owner) as session:
        # The migration leaves historical input intact and the summary nullable.
        session.execute(
            update(Alert)
            .where(Alert.id == record.id)
            .values(risk_score=None, risk_level=None, risk_calculation_id=None)
        )
        session.commit()


@pytest.mark.parametrize("role", ["soc_manager", "soc_analyst", "read_only"])
def test_non_admin_and_source_cannot_write_backfilled_risk(
    case: Case, admin: Login, role: str
) -> None:
    record = seed_signals(case, admin)[0]
    legacy_projection(case, record)
    principal = user(case, admin, role)
    source = enroll(admin)
    before = risk_counts(case)
    assert backfill(principal).status_code == 403
    denied = admin.client.post(
        "/api/v1/risk/backfill", json={"limit": 100}, headers=source.authorization
    )
    assert denied.status_code == 401
    assert risk_counts(case) == before
    assert alerts(case)[0].risk_score is None


@pytest.mark.parametrize("change", ["role", "disabled", "revoked", "absolute", "idle"])
@pytest.mark.parametrize("operation", ["backfill", "alert", "incident"])
def test_risk_mutation_rechecks_current_authority_after_waiting_for_admin_lock(
    case: Case, admin: Login, change: str, operation: str
) -> None:
    record = seed_signals(case, admin)[0]
    if operation == "backfill":
        legacy_projection(case, record)
    incident = make_case(admin, [record]) if operation == "incident" else None
    operator = user(case, admin, "admin")
    before = risk_counts(case)
    reached_lock = Event()
    engine = operator.client.app.state.database.engine

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
                if operation == "backfill":
                    future = executor.submit(backfill, operator)
                else:
                    identifier = incident["id"] if incident is not None else str(record.id)
                    version = incident["version"] if incident is not None else record.version
                    future = executor.submit(
                        operator.client.post,
                        f"/api/v1/{operation}s/{identifier}/risk/recalculate",
                        json={},
                        headers={**operator.authorization, "If-Match": f'"{version}"'},
                    )
                try:
                    assert reached_lock.wait(timeout=3), (
                        "Risk mutation did not reach authority lock"
                    )
                    with Session(case.database.owner) as session:
                        user_id, now = UUID(operator.user_id), utcnow()
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
    assert risk_counts(case) == before
    assert alerts(case)[0].risk_score == (None if operation == "backfill" else 45)


def test_false_positive_reduces_case_risk_and_preserves_prior_assessments(
    case: Case, admin: Login
) -> None:
    records = seed_signals(case, admin, count=2)
    incident = make_case(admin, records)
    # High baseline 45 + one independent repeated signal 3 + one extra event 2.
    assert incident["risk_score"] == 50
    before = risk_counts(case)
    response = admin.client.patch(
        f"/api/v1/alerts/{records[0].id}",
        json={"status": "false_positive"},
        headers={**admin.authorization, "If-Match": f'"{records[0].version}"'},
    )
    assert response.status_code == 200, response.text
    assert response.json()["version"] == records[0].version + 1
    current = current_case(admin, incident["id"])
    assert current["risk_score"] == 45
    assert current["version"] == incident["version"]
    assert current["updated_at"] == incident["updated_at"]
    assert current["alert_count"] == 2
    assert current["confidence"] is None
    assert risk_counts(case)["risk_calculations"] > before["risk_calculations"]


def test_analyst_severity_and_owner_do_not_invent_a_detection_signal(
    case: Case, admin: Login
) -> None:
    record = seed_signals(case, admin)[0]
    incident = make_case(admin, [record])
    assert incident["risk_score"] == 45 and incident["confidence"] is None
    response = admin.client.patch(
        f"/api/v1/incidents/{incident['id']}",
        json={"severity": "critical", "owner_id": admin.user_id},
        headers={**admin.authorization, "If-Match": f'"{incident["version"]}"'},
    )
    assert response.status_code == 200, response.text
    current = response.json()
    assert current["risk_score"] == 45 and current["confidence"] is None
    assert current["version"] == incident["version"] + 1
    assert current["severity"] == "critical" and current["owner_id"] == admin.user_id


@pytest.mark.parametrize("table", ["alerts", "incidents"])
def test_runtime_still_cannot_write_a_score_directly(case: Case, admin: Login, table: str) -> None:
    record = seed_signals(case, admin)[0]
    incident = make_case(admin, [record])
    identifier = record.id if table == "alerts" else UUID(incident["id"])
    before = risk_counts(case)
    with Session(case.database.runtime) as session:
        with pytest.raises(DBAPIError) as rejected:
            session.execute(
                text(f"UPDATE {table} SET risk_score=100 WHERE id=:id"), {"id": identifier}
            )
        assert getattr(rejected.value.orig, "sqlstate", None) == "42501"
        session.rollback()
    assert risk_counts(case) == before
    assert current_case(admin, incident["id"])["risk_score"] == 45


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE risk_calculations SET id=id",
        "DELETE FROM risk_calculations",
        "TRUNCATE risk_calculations",
    ],
)
def test_runtime_cannot_rewrite_delete_or_truncate_risk_history(
    case: Case, admin: Login, statement: str
) -> None:
    seed_signals(case, admin)
    before = risk_counts(case)
    assert before["risk_calculations"] >= 2
    with Session(case.database.runtime) as session:
        with pytest.raises(DBAPIError) as rejected:
            session.execute(text(statement))
        assert getattr(rejected.value.orig, "sqlstate", None) == "42501"
        session.rollback()
    assert risk_counts(case) == before


def test_failed_false_positive_audit_rolls_back_all_related_risk(case: Case, admin: Login) -> None:
    records = seed_signals(case, admin, count=2)
    incident = make_case(admin, records)
    before = risk_counts(case)
    with case.database.owner.begin() as connection:
        connection.execute(text("REVOKE INSERT ON audit_logs FROM aegis_app"))
    try:
        response = admin.client.patch(
            f"/api/v1/alerts/{records[0].id}",
            json={"status": "false_positive"},
            headers={**admin.authorization, "If-Match": f'"{records[0].version}"'},
        )
        assert response.status_code == 503, response.text
    finally:
        with case.database.owner.begin() as connection:
            connection.execute(text("GRANT INSERT ON audit_logs TO aegis_app"))
    assert risk_counts(case) == before
    preserved = next(record for record in alerts(case) if record.id == records[0].id)
    assert preserved.status == "new" and preserved.version == records[0].version
    current = current_case(admin, incident["id"])
    assert current["risk_score"] == 50 and current["version"] == incident["version"]


def test_failed_backfill_audit_rolls_back_projection_and_retry_is_idempotent(
    case: Case, admin: Login
) -> None:
    record = seed_signals(case, admin)[0]
    legacy_projection(case, record)
    before = risk_counts(case)
    with case.database.owner.begin() as connection:
        connection.execute(text("REVOKE INSERT ON audit_logs FROM aegis_app"))
    try:
        response = backfill(admin)
        assert response.status_code == 503, response.text
    finally:
        with case.database.owner.begin() as connection:
            connection.execute(text("GRANT INSERT ON audit_logs TO aegis_app"))
    assert risk_counts(case) == before
    assert alerts(case)[0].risk_score is None
    recovered = backfill(admin)
    assert recovered.status_code == 200, recovered.text
    assert alerts(case)[0].risk_score == 45
    restored_calculations = risk_counts(case)["risk_calculations"]
    repeated = backfill(admin)
    assert repeated.status_code == 200, repeated.text
    assert risk_counts(case)["risk_calculations"] == restored_calculations


@pytest.mark.parametrize("corruption", ["hash", "scope", "empty"])
def test_backfill_rejects_invalid_evidence_before_restoring_assessment(
    case: Case, admin: Login, corruption: str
) -> None:
    record = seed_signals(case, admin)[0]
    legacy_projection(case, record)
    proof = deepcopy(record.event_snapshot)
    with Session(case.database.owner) as session:
        if corruption == "hash":
            proof["process"]["command_line"] = "altered-without-updating-proof-hash"
            session.execute(update(Alert).where(Alert.id == record.id).values(event_snapshot=proof))
        elif corruption == "scope":
            session.execute(update(Alert).where(Alert.id == record.id).values(dataset_id=uuid4()))
        else:
            session.execute(update(Alert).where(Alert.id == record.id).values(event_snapshot={}))
        session.commit()
    before = risk_counts(case)
    response = backfill(admin)
    assert response.status_code == 409, response.text
    assert risk_counts(case) == before
    assert alerts(case)[0].risk_score is None


def test_concurrent_backfills_restore_once_without_editing_alert_version(
    case: Case, admin: Login
) -> None:
    record = seed_signals(case, admin)[0]
    legacy_projection(case, record)
    other = case.login("initial_admin", admin.password)
    before = risk_counts(case)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(backfill, principal) for principal in (admin, other)]
        responses = [future.result(timeout=15) for future in futures]
    assert [response.status_code for response in responses] == [200, 200]
    current = alerts(case)[0]
    assert current.risk_score == 45 and current.version == record.version
    assert current.updated_at == record.updated_at
    # Restoring a cleared current pointer creates exactly one revision. The
    # second request observes the committed projection and cannot duplicate it.
    assert risk_counts(case)["risk_calculations"] == before["risk_calculations"] + 1


def test_older_assessment_cannot_replace_the_newest_projection(case: Case, admin: Login) -> None:
    records = seed_signals(case, admin, count=2)
    incident = make_case(admin, records)
    with Session(case.database.runtime) as session:
        previous = session.scalar(
            text(
                "SELECT id FROM risk_calculations "
                "WHERE subject_type='incident' AND subject_id=:id "
                "ORDER BY subject_revision DESC LIMIT 1"
            ),
            {"id": UUID(incident["id"])},
        )
        assert previous is not None
    response = admin.client.patch(
        f"/api/v1/alerts/{records[0].id}",
        json={"status": "false_positive"},
        headers={**admin.authorization, "If-Match": f'"{records[0].version}"'},
    )
    assert response.status_code == 200, response.text
    assert current_case(admin, incident["id"])["risk_score"] == 45
    before = risk_counts(case)
    with Session(case.database.runtime) as session:
        with pytest.raises(DBAPIError) as rejected:
            session.execute(text("SELECT public.aegis_apply_risk(:id)"), {"id": previous})
        assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
        session.rollback()
    assert risk_counts(case) == before
    assert current_case(admin, incident["id"])["risk_score"] == 45


def simulated_input(count: int = 3) -> dict[str, Any]:
    """Opaque fixture identities avoid creating any privileged domain record."""
    beginning = datetime(2026, 10, 1, 12, tzinfo=UTC)
    return {
        "evidence": [
            {
                "id": str(UUID(int=number + 1)),
                "timestamp": (beginning + timedelta(seconds=number)).isoformat(),
                "sha256": f"{number + 1:064x}",
            }
            for number in range(count)
        ],
        "signals": [],
    }


def simulated_signal(identifier: str, evidence_ids: list[str], **changes: Any) -> dict[str, Any]:
    return {
        "id": identifier,
        "family": "suspicious_execution",
        "severity": "high",
        "evidence_ids": evidence_ids,
        **changes,
    }


def simulation(principal: Login, value: dict[str, Any]) -> Any:
    return principal.client.post("/api/v1/risk/test", json=value, headers=principal.authorization)


def test_transitive_same_family_proof_overlap_counts_once_and_order_is_deterministic(
    case: Case, admin: Login
) -> None:
    value = simulated_input()
    identities = [item["id"] for item in value["evidence"]]
    value["signals"] = [
        simulated_signal("one", identities[:1]),
        simulated_signal("bridge", identities[:2]),
        simulated_signal("last", identities[1:]),
    ]
    before = risk_counts(case)
    first = simulation(admin, value)
    assert first.status_code == 200, first.text
    result = first.json()
    # One overlapping behavioral unit contributes no repeat bonus. Three unique
    # events add only 2 * (3 - 1), independently of four cited references.
    assert result["score"] == 49 and result["raw_score"] == 49
    assert len(result["signal_units"]) == 1
    shuffled = deepcopy(value)
    shuffled["evidence"].reverse()
    shuffled["signals"].reverse()
    for signal in shuffled["signals"]:
        signal["evidence_ids"].reverse()
    second = simulation(admin, shuffled)
    assert second.status_code == 200, second.text
    assert second.json() == result
    assert risk_counts(case) == before


@pytest.mark.parametrize("confidence, expected", [(0, 0), (64, 28), (65, 29), (67, 30), (100, 45)])
def test_trusted_confidence_uses_integer_floor_and_exact_band_boundaries(
    case: Case, admin: Login, confidence: int, expected: int
) -> None:
    value = simulated_input(1)
    provenance = {
        "source": "review-calibration-fixture",
        "version": "fixture-1",
        "snapshot_sha256": "f" * 64,
        "as_of": "2026-09-30T12:00:00Z",
    }
    value["signals"] = [
        simulated_signal(
            "confidence-proof",
            [value["evidence"][0]["id"]],
            confidence=confidence,
            confidence_provenance=provenance,
        )
    ]
    result = simulation(admin, value)
    assert result.status_code == 200, result.text
    assert result.json()["score"] == expected
    assert result.json()["level"] == ("low" if expected < 30 else "medium")
    assert result.json()["confidence_status"] == "known"


@pytest.mark.parametrize(
    "corruption",
    [
        "duplicate_evidence",
        "dangling_signal",
        "untrusted_confidence",
        "live_replay",
        "replay_live",
        "extra",
    ],
)
def test_pure_simulation_rejects_ambiguous_or_unbounded_claims_without_domain_writes(
    case: Case, admin: Login, corruption: str
) -> None:
    value = simulated_input(1)
    value["signals"] = [simulated_signal("one", [value["evidence"][0]["id"]])]
    if corruption == "duplicate_evidence":
        value["evidence"].append(deepcopy(value["evidence"][0]))
    elif corruption == "dangling_signal":
        value["signals"][0]["evidence_ids"] = [str(uuid4())]
    elif corruption == "untrusted_confidence":
        value["signals"][0]["confidence"] = 100
    elif corruption == "live_replay":
        value["run_id"] = str(uuid4())
    elif corruption == "replay_live":
        value["mode"] = "replay"
        value["dataset_id"] = str(uuid4())
    else:
        value["risk_score"] = 100
    before = risk_counts(case)
    response = simulation(admin, value)
    assert response.status_code == 422, response.text
    assert risk_counts(case) == before


def context_fixture(kind: str, identities: list[str], **changes: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "value": "confirmed_malicious" if kind == "confirmed_history" else "malicious",
        "evidence_ids": identities,
        "provenance": {
            "source": "independent-context-review",
            "version": "fixture-1",
            "snapshot_sha256": "e" * 64,
            "as_of": "2026-09-30T12:00:00Z",
        },
        **changes,
    }


@pytest.mark.parametrize(
    "conflict", ["self", "alias", "overlap", "future", "old", "identity", "mode", "dataset"]
)
def test_history_bonus_excludes_current_related_later_and_other_scope_cases(
    case: Case, admin: Login, conflict: str
) -> None:
    value = simulated_input(1)
    identity = value["evidence"][0]["id"]
    value["signals"] = [simulated_signal("one", [identity])]
    current_id, previous_id = str(uuid4()), str(uuid4())
    value.update({"subject_id": current_id, "subject_keys": ["host:registered-host-17"]})
    fact = context_fixture(
        "confirmed_history",
        [identity],
        subject_key="host:registered-host-17",
        observed_at="2026-09-29T12:00:00Z",
        prior_incident_id=previous_id,
        prior_evidence_ids=[str(UUID(int=999))],
        prior_mode="live",
        prior_run_id=str(UUID(int=0)),
    )
    if conflict == "self":
        fact["prior_incident_id"] = current_id
    elif conflict == "alias":
        value["excluded_incident_ids"] = [previous_id]
    elif conflict == "overlap":
        fact["prior_evidence_ids"] = [identity]
    elif conflict == "future":
        fact["observed_at"] = "2026-10-02T12:00:00Z"
    elif conflict == "old":
        fact["observed_at"] = "2026-08-01T12:00:00Z"
    elif conflict == "identity":
        fact["subject_key"] = "host:other-host"
    elif conflict == "mode":
        fact["prior_mode"] = "replay"
        fact["prior_run_id"] = str(uuid4())
        fact["prior_dataset_id"] = str(uuid4())
    else:
        value.update({"mode": "replay", "dataset_id": str(uuid4()), "run_id": str(uuid4())})
        fact.update(
            {"prior_mode": "replay", "prior_dataset_id": str(uuid4()), "prior_run_id": str(uuid4())}
        )
    value["contexts"] = [fact]
    response = simulation(admin, value)
    assert response.status_code == 200, response.text
    assert response.json()["score"] == 45
    assert (
        next(part for part in response.json()["components"] if part["code"] == "H")["points"] == 0
    )


@pytest.mark.parametrize(
    "state, bonus",
    [
        ("inactive", 0),
        ("expired", 0),
        ("expired_as_of", 0),
        ("low_confidence", 5),
        ("verified", 15),
    ],
)
def test_ioc_context_uses_v4_and_preserves_v3_eligibility_and_history(
    case: Case, admin: Login, state: str, bonus: int
) -> None:
    value = simulated_input(1)
    identities = [value["evidence"][0]["id"]]
    value["signals"] = [simulated_signal("one", identities)]
    fact = context_fixture("ioc_reputation", identities, confidence=80)
    if state == "inactive":
        fact["active"] = False
    elif state == "expired":
        fact["expires_at"] = "2026-10-01T11:59:59Z"
    elif state == "expired_as_of":
        fact["expires_at"] = "2026-10-01T18:00:00Z"
        fact["provenance"]["as_of"] = "2026-10-02T00:00:00Z"
    elif state == "low_confidence":
        fact["confidence"] = 79
    value["contexts"] = [fact]
    # V4 gives qualifying malicious records a small floor; the unchanged v3
    # implementation must still reproduce its historical confidence threshold.
    legacy_bonus = 0 if state == "low_confidence" else bonus
    assert engine.calculate(RiskInput.model_validate(value)).score == 45 + legacy_bonus
    response = simulation(admin, value)
    assert response.status_code == 200, response.text
    assert response.json()["policy_version"] == engine_v4.POLICY_VERSION
    assert response.json()["policy_hash"] == engine_v4.POLICY_HASH
    assert (
        next(part for part in response.json()["components"] if part["code"] == "I")["points"]
        == bonus
    )
    assert response.json()["score"] == 45 + bonus


def test_several_tactic_labels_on_one_behavior_do_not_create_multi_behavior_bonus(
    case: Case, admin: Login
) -> None:
    value = simulated_input(1)
    identities = [value["evidence"][0]["id"]]
    value["signals"] = [simulated_signal("one", identities)]
    value["contexts"] = [
        context_fixture("attack_tactics", identities, value=tactic)
        for tactic in ("TA0001", "TA0002", "TA0003", "TA0004")
    ]
    response = simulation(admin, value)
    assert response.status_code == 200, response.text
    assert response.json()["score"] == 45
    assert (
        next(part for part in response.json()["components"] if part["code"] == "T")["points"] == 0
    )


def test_ingested_extension_claims_cannot_supply_trusted_production_context(
    case: Case, admin: Login
) -> None:
    claims = {
        "confidence": 100,
        "risk_score": 100,
        "ip_reputation": "malicious",
        "host_criticality": "critical",
        "user_importance": "critical",
        "prior_privileges": "administrator",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0004"],
        "confirmed_history": "confirmed_malicious",
    }
    documents = trace_documents(
        case,
        admin,
        [
            {
                "event": {"category": "authentication", "outcome": "success"},
                "extensions": claims,
            },
            {
                "event": {"category": "iam", "code": "4732"},
                "user": {"name": "alice", "realm": "LAB", "target": {"name": "bob"}},
                "extensions": {**claims, "group": {"id": "S-1-5-32-544"}},
            },
        ],
    )
    assert all(document["extensions"]["risk_score"] == 100 for document in documents)
    from app.modules.correlation.processing import process_once

    process_once(
        processing_database(case), case.database.settings, now=utcnow() + timedelta(seconds=121)
    )
    with Session(case.database.runtime) as session:
        record = session.scalar(
            select(Alert).where(Alert.rule_id == "login_then_local_admin_change")
        )
        assert record is not None and record.risk_score == 47
        response = admin.client.get(f"/api/v1/alerts/{record.id}", headers=admin.authorization)
    assert response.status_code == 200, response.text
    assessment = response.json()["risk_explanation"]
    assert assessment["confidence_status"] == "unknown"
    for code in ("A", "U", "I", "T", "H", "P"):
        part = next(item for item in assessment["components"] if item["code"] == code)
        assert part["points"] == 0 and part["status"] == "unknown"


@pytest.mark.parametrize("corruption", ["predicate", "order", "window", "host_identity"])
def test_recalculation_revalidates_full_temporal_proof_even_with_recomputed_hashes(
    case: Case, admin: Login, corruption: str
) -> None:
    record = correlated_alert(case, admin)
    proof = deepcopy(record.event_snapshots)
    document = proof[0]["event_snapshot"]
    if corruption == "predicate":
        document["event"]["outcome"] = "success"
    elif corruption == "order":
        document["timestamp"] = (record.event_timestamp + timedelta(seconds=1)).isoformat()
    elif corruption == "window":
        document["timestamp"] = (record.event_timestamp - timedelta(minutes=20)).isoformat()
    else:
        document["host"]["id"] = "unrelated-registered-host"
    proof[0]["event_sha256"] = hashlib.sha256(canonical_json(document)).hexdigest()
    with Session(case.database.owner) as session:
        session.execute(update(Alert).where(Alert.id == record.id).values(event_snapshots=proof))
        session.commit()
    before = risk_counts(case)
    response = admin.client.post(
        f"/api/v1/alerts/{record.id}/risk/recalculate",
        json={},
        headers={**admin.authorization, "If-Match": f'"{record.version}"'},
    )
    assert response.status_code == 409, response.text
    assert risk_counts(case) == before


@pytest.mark.parametrize("subject", ["alert", "incident"])
def test_recalculation_is_version_guarded_and_does_not_modify_analyst_version(
    case: Case, admin: Login, subject: str
) -> None:
    record = seed_signals(case, admin)[0]
    incident = make_case(admin, [record])
    identifier = str(record.id) if subject == "alert" else incident["id"]
    version = record.version if subject == "alert" else incident["version"]
    path = f"/api/v1/{subject}s/{identifier}/risk/recalculate"
    before = risk_counts(case)
    missing = admin.client.post(path, json={}, headers=admin.authorization)
    assert missing.status_code == 428, missing.text
    stale = admin.client.post(
        path, json={}, headers={**admin.authorization, "If-Match": f'"{version + 1}"'}
    )
    assert stale.status_code == 412, stale.text
    first = admin.client.post(
        path, json={}, headers={**admin.authorization, "If-Match": f'"{version}"'}
    )
    assert first.status_code == 200, first.text
    assert risk_counts(case)["risk_calculations"] == before["risk_calculations"]
    assert alerts(case)[0].version == record.version
    assert current_case(admin, incident["id"])["version"] == incident["version"]


def test_unrelated_uncited_evidence_does_not_inflate_a_recognized_signal(
    case: Case, admin: Login
) -> None:
    value = simulated_input(8)
    value["signals"] = [simulated_signal("one", [value["evidence"][0]["id"]])]
    response = simulation(admin, value)
    assert response.status_code == 200, response.text
    assert response.json()["score"] == 45
    event_bonus = next(part for part in response.json()["components"] if part["code"] == "E")
    assert event_bonus["points"] == 0


def test_production_input_builder_rejects_other_scope_before_persistence(
    case: Case, admin: Login
) -> None:
    from app.core.errors import ApiError
    from app.modules.risk.inputs import build_input

    records = seed_signals(case, admin)
    before = risk_counts(case)
    with pytest.raises(ApiError) as rejected:
        build_input(
            records,
            subject_id=records[0].id,
            mode="replay",
            dataset_id=uuid4(),
            run_id=uuid4(),
            exclude_false_positive=False,
        )
    assert rejected.value.status == 409
    assert risk_counts(case) == before


def test_single_event_alert_cannot_smuggle_unrelated_extra_proof_into_risk(
    case: Case, admin: Login
) -> None:
    record = seed_signals(case, admin)[0]
    extra_id = normalize_events(
        case, admin, [powershell("powershell.exe -NoProfile -Command Get-Date")]
    )[0]
    with Session(case.database.runtime) as session:
        extra = session.get(NormalizedEvent, extra_id)
        assert extra is not None
        document = deepcopy(extra.document)
    proof = deepcopy(record.event_snapshots) or [
        {
            "event_id": str(record.event_id),
            "event_sha256": record.event_sha256,
            "event_snapshot": record.event_snapshot,
        }
    ]
    proof.append(
        {
            "event_id": str(extra_id),
            "event_sha256": hashlib.sha256(canonical_json(document)).hexdigest(),
            "event_snapshot": document,
        }
    )
    with Session(case.database.owner) as session:
        session.execute(update(Alert).where(Alert.id == record.id).values(event_snapshots=proof))
        session.commit()
    before = risk_counts(case)
    response = admin.client.post(
        f"/api/v1/alerts/{record.id}/risk/recalculate",
        json={},
        headers={**admin.authorization, "If-Match": f'"{record.version}"'},
    )
    assert response.status_code == 409, response.text
    assert risk_counts(case) == before


@pytest.mark.parametrize("table", ["alerts", "incidents"])
def test_storage_rejects_partial_null_risk_triplet_even_for_database_owner(
    case: Case, admin: Login, table: str
) -> None:
    record = seed_signals(case, admin)[0]
    incident = make_case(admin, [record])
    identifier = record.id if table == "alerts" else UUID(incident["id"])
    before = risk_counts(case)
    with Session(case.database.owner) as session:
        # Existing score and calculation FK are valid. SQL NULL must not turn a
        # false integrity condition into an accepted UNKNOWN CHECK result.
        with pytest.raises(DBAPIError) as rejected:
            session.execute(
                text(f"UPDATE {table} SET risk_level=NULL WHERE id=:id"), {"id": identifier}
            )
        assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
        session.rollback()
    assert risk_counts(case) == before
    response = admin.client.get(f"/api/v1/{table}/{identifier}", headers=admin.authorization)
    assert response.status_code == 200, response.text
    assert response.json()["risk_score"] == 45 and response.json()["risk_level"] == "medium"


def test_inactive_asset_context_does_not_grant_critical_host_bonus(
    case: Case, admin: Login
) -> None:
    value = simulated_input(1)
    identities = [value["evidence"][0]["id"]]
    value["signals"] = [simulated_signal("one", identities)]
    value["subject_keys"] = ["host:registered-host-17"]
    value["contexts"] = [
        context_fixture(
            "host_criticality",
            identities,
            value="critical",
            subject_key="host:registered-host-17",
            active=False,
        )
    ]
    response = simulation(admin, value)
    assert response.status_code == 200, response.text
    assert response.json()["score"] == 45


def test_expired_tactic_mapping_cannot_supply_second_verified_behavior(
    case: Case, admin: Login
) -> None:
    value = simulated_input(2)
    identities = [item["id"] for item in value["evidence"]]
    value["signals"] = [
        simulated_signal("one", identities[:1]),
        simulated_signal("two", identities[1:], family="authentication_attack"),
    ]
    value["contexts"] = [
        context_fixture("attack_tactics", identities[:1], value="TA0002"),
        context_fixture(
            "attack_tactics", identities[1:], value="TA0006", expires_at="2026-10-01T11:59:59Z"
        ),
    ]
    response = simulation(admin, value)
    assert response.status_code == 200, response.text
    # D45 + C3 + E2. Only one tactic mapping remains valid, hence T0.
    assert response.json()["score"] == 50
