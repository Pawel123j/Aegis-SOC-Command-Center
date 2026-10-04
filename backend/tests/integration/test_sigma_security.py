"""Independent authority, append-only storage and original Sigma proof checks."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import timedelta
from threading import Event
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core.permissions import Role
from app.infrastructure.database import ADMIN_LOCK_ID, utcnow
from app.modules.alerts.models import Alert
from app.modules.auth.models import AuthSession
from app.modules.ingestion.schemas import canonical_json
from app.modules.sigma.compiler import compile_rule
from app.modules.sigma.evaluator import evaluate
from app.modules.sigma.models import SigmaRuleVersion
from app.modules.users.models import User

from .helper_ingestion import enroll, processing_database
from .helper_sigma import definition, document, domain_counts, import_rule, publish
from .helpers import Case, Login
from .test_initial_alerts import alerts, detect_once, normalize_events, powershell, user

pytestmark = pytest.mark.integration
BASE = "/api/v1/sigma"


def state_counts(case: Case) -> dict[str, int]:
    """Rejected authority is audited; it cannot change detection or evidence state."""
    result = domain_counts(case)
    result.pop("audit_logs")
    return result


def current(principal: Login, rule: dict[str, Any]) -> dict[str, Any]:
    response = principal.client.get(f"{BASE}/rules/{rule['id']}", headers=principal.authorization)
    assert response.status_code == 200, response.text
    return dict(response.json())


def mutate(
    principal: Login, operation: str, rule: dict[str, Any], source: str | None = None
) -> Any:
    headers = {**principal.authorization, "If-Match": f'"{rule["version"]}"'}
    if operation == "import":
        return principal.client.post(
            f"{BASE}/rules", json={"yaml": source or definition()}, headers=headers
        )
    if operation == "revision":
        return principal.client.post(
            f"{BASE}/rules/{rule['id']}/versions",
            json={"yaml": source or definition(rule["id"], title="Reviewed second revision")},
            headers=headers,
        )
    return principal.client.patch(
        f"{BASE}/rules/{rule['id']}", json={"enabled": True}, headers=headers
    )


@pytest.mark.parametrize("role", ["admin", "soc_manager", "soc_analyst", "read_only"])
def test_sigma_role_permissions_apply_to_each_read_import_publish_and_test(
    case: Case, admin: Login, role: str
) -> None:
    rule = import_rule(admin)
    principal = admin if role == "admin" else user(case, admin, role)
    ids = normalize_events(case, admin, [powershell("powershell -Command Get-Date")])
    before = state_counts(case)
    for route in ("/capabilities", "/rules", f"/rules/{rule['id']}"):
        response = principal.client.get(BASE + route, headers=principal.authorization)
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
    response = principal.client.post(
        BASE + "/validate", json={"yaml": rule["definition_yaml"]}, headers=principal.authorization
    )
    assert response.status_code == 200 and response.json()["valid"] is True
    response = principal.client.post(
        BASE + "/test",
        json={"yaml": rule["definition_yaml"], "events": [document(case, ids[0])]},
        headers=principal.authorization,
    )
    assert response.status_code == (403 if role == "read_only" else 200), response.text
    assert state_counts(case) == before
    for operation in ("import", "revision", "publish"):
        response = mutate(principal, operation, rule)
        if role in {"soc_analyst", "read_only"}:
            assert response.status_code == 403, response.text
            assert response.json()["code"] == "forbidden"
            assert state_counts(case) == before
        else:
            assert response.status_code == (200 if operation == "publish" else 201), response.text
            if operation == "revision":
                rule = response.json()


@pytest.mark.parametrize("credential", ["anonymous", "source"])
def test_source_and_anonymous_credentials_cannot_access_any_sigma_route(
    case: Case, admin: Login, credential: str
) -> None:
    rule = import_rule(admin)
    headers = {} if credential == "anonymous" else enroll(admin).authorization
    client = case.client()
    before = state_counts(case)
    routes = [
        ("GET", "/capabilities", None),
        ("GET", "/rules", None),
        ("GET", f"/rules/{rule['id']}", None),
        ("POST", "/validate", {"yaml": rule["definition_yaml"]}),
        ("POST", "/test", {"yaml": rule["definition_yaml"], "events": []}),
        ("POST", "/rules", {"yaml": definition()}),
        ("POST", f"/rules/{rule['id']}/versions", {"yaml": definition(rule["id"])}),
        ("PATCH", f"/rules/{rule['id']}", {"enabled": True}),
    ]
    for method, path, body in routes:
        response = client.request(
            method, BASE + path, json=body, headers={**headers, "If-Match": '"1"'}
        )
        assert response.status_code == 401, response.text
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["code"] == "unauthorized"
    assert state_counts(case) == before


@pytest.mark.parametrize("change", ["role", "disabled", "revoked", "absolute", "idle"])
@pytest.mark.parametrize("operation", ["import", "revision", "publish"])
def test_sigma_mutations_recheck_user_and_session_after_waiting_for_authority_lock(
    case: Case, admin: Login, operation: str, change: str
) -> None:
    rule = import_rule(admin)
    operator = user(case, admin, "soc_manager")
    before = state_counts(case)
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
                future = executor.submit(mutate, operator, operation, rule)
                try:
                    assert reached_lock.wait(timeout=3), (
                        "Sigma mutation did not reach authority lock"
                    )
                    with Session(case.database.owner) as db:
                        identity, now = UUID(operator.user_id), utcnow()
                        if change in {"role", "disabled"}:
                            db.execute(
                                update(User)
                                .where(User.id == identity)
                                .values(
                                    **(
                                        {"role": Role.READ_ONLY}
                                        if change == "role"
                                        else {"enabled": False}
                                    )
                                )
                            )
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
                response = future.result(timeout=10)
    finally:
        event.remove(engine, "before_cursor_execute", observe_lock)
    assert response.status_code == 403 and response.json()["code"] == "forbidden", response.text
    assert state_counts(case) == before and current(admin, rule) == rule


@pytest.mark.parametrize("table", ["sigma_rules", "sigma_rule_versions"])
@pytest.mark.parametrize("operation", ["UPDATE", "DELETE", "TRUNCATE"])
def test_runtime_cannot_rewrite_or_erase_committed_sigma_definitions(
    case: Case, admin: Login, table: str, operation: str
) -> None:
    rule = import_rule(admin)
    before = domain_counts(case)
    statement = {
        "UPDATE": f"UPDATE {table} SET id=id",
        "DELETE": f"DELETE FROM {table}",
        "TRUNCATE": f"TRUNCATE {table}",
    }[operation]
    with case.database.runtime.connect() as db:
        for allowed in ("SELECT", "INSERT"):
            assert db.scalar(
                text("SELECT has_table_privilege(current_user,:table,:permission)"),
                {"table": table, "permission": allowed},
            )
        db.rollback()
        with pytest.raises(DBAPIError) as rejected:
            db.execute(text(statement))
        assert getattr(rejected.value.orig, "sqlstate", None) == "42501"
        db.rollback()
    assert domain_counts(case) == before and current(admin, rule) == rule


@pytest.mark.parametrize("operation", ["insert_deployment", "version_builtin", "version_sigma"])
def test_sigma_migration_does_not_grant_broad_deployment_creation_or_version_updates(
    case: Case, admin: Login, operation: str
) -> None:
    rule = import_rule(admin)
    identifier = f"sigma:{rule['id']}"
    statement, parameters = {
        "insert_deployment": (
            "INSERT INTO rule_deployments(id,rule_version,enabled) VALUES (:id,'9',true)",
            {"id": "uncontrolled-deployment"},
        ),
        "version_builtin": (
            "UPDATE rule_deployments SET rule_version='9' WHERE id=:id",
            {"id": "powershell-suspicious-command"},
        ),
        "version_sigma": (
            "UPDATE rule_deployments SET rule_version='9' WHERE id=:id",
            {"id": identifier},
        ),
    }[operation]
    before = domain_counts(case)
    with case.database.runtime.connect() as db:
        assert db.scalar(
            text(
                "SELECT has_function_privilege(current_user,"
                "'public.aegis_select_sigma_revision(uuid,integer,uuid)','EXECUTE')"
            )
        )
        assert not db.scalar(
            text(
                "SELECT has_column_privilege(current_user,"
                "'rule_deployments','rule_version','UPDATE')"
            )
        )
        db.rollback()
        with pytest.raises(DBAPIError) as rejected:
            db.execute(text(statement), parameters)
        assert getattr(rejected.value.orig, "sqlstate", None) == "42501"
        db.rollback()
    with case.database.owner.connect() as db:
        assert not db.scalar(
            text(
                "SELECT EXISTS (SELECT 1 FROM pg_proc p, LATERAL aclexplode(p.proacl) a "
                "WHERE p.oid='public.aegis_select_sigma_revision(uuid,integer,uuid)'::regprocedure "
                "AND a.grantee=0 AND a.privilege_type='EXECUTE')"
            )
        )
    assert domain_counts(case) == before and current(admin, rule) == rule


@pytest.mark.parametrize("actor", ["analyst", "read_only", "disabled", "unknown"])
def test_sigma_selector_sql_function_checks_current_actor_role_and_enabled_state(
    case: Case, admin: Login, actor: str
) -> None:
    rule = import_rule(admin)
    principal = user(
        case,
        admin,
        "soc_manager"
        if actor == "disabled"
        else "soc_analyst"
        if actor == "analyst"
        else "read_only",
    )
    identity = UUID(principal.user_id) if actor != "unknown" else uuid4()
    if actor == "disabled":
        with Session(case.database.owner) as db:
            db.execute(update(User).where(User.id == identity).values(enabled=False))
            db.commit()
    before = domain_counts(case)
    with case.database.runtime.connect() as db:
        with pytest.raises(DBAPIError) as rejected:
            db.execute(
                text("SELECT public.aegis_select_sigma_revision(:rule,1,:actor)"),
                {"rule": UUID(rule["id"]), "actor": identity},
            )
        assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
        db.rollback()
    assert domain_counts(case) == before and current(admin, rule) == rule


def test_sigma_identity_cannot_target_builtin_deployment_and_selector_cannot_skip_revision(
    case: Case, admin: Login
) -> None:
    rule = import_rule(admin)
    before = domain_counts(case)
    with case.database.runtime.connect() as db:
        with pytest.raises(DBAPIError) as rejected:
            db.execute(
                text(
                    "INSERT INTO sigma_rules(id,detection_id,created_by) "
                    "VALUES (:id,:target,:actor)"
                ),
                {
                    "id": uuid4(),
                    "target": "powershell-suspicious-command",
                    "actor": UUID(admin.user_id),
                },
            )
        assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
        db.rollback()
        for selected in (1, 2, 20):
            with pytest.raises(DBAPIError) as rejected:
                db.execute(
                    text("SELECT public.aegis_select_sigma_revision(:rule,:selected,:actor)"),
                    {"rule": UUID(rule["id"]), "selected": selected, "actor": UUID(admin.user_id)},
                )
            assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
            db.rollback()
    assert domain_counts(case) == before and current(admin, rule) == rule


@pytest.mark.parametrize("operation", ["import", "revision", "publish", "coverage"])
def test_corrupt_persisted_current_revision_returns_safe_unavailable_without_writes(
    case: Case, admin: Login, operation: str
) -> None:
    rule = import_rule(admin)
    with Session(case.database.owner) as db:
        db.execute(
            update(SigmaRuleVersion)
            .where(SigmaRuleVersion.id == UUID(rule["revision_id"]))
            .values(compiled_sha256="f" * 64)
        )
        db.commit()
    before = domain_counts(case)
    response = (
        admin.client.get("/api/v1/mitre/coverage", headers=admin.authorization)
        if operation == "coverage"
        else mutate(
            admin, operation, rule, rule["definition_yaml"] if operation == "import" else None
        )
    )
    assert response.status_code == 503, response.text
    assert response.json()["code"] == "sigma_revision_unavailable"
    assert domain_counts(case) == before


@pytest.mark.parametrize("operation", ["revision", "publish"])
def test_sigma_revision_projection_and_publish_roll_back_if_audit_cannot_append(
    case: Case, admin: Login, operation: str
) -> None:
    rule = import_rule(admin)
    if operation == "revision":
        rule = publish(admin, rule)
    before = domain_counts(case)
    with case.database.owner.begin() as db:
        db.execute(text("REVOKE INSERT ON audit_logs FROM aegis_app"))
    try:
        response = mutate(admin, operation, rule)
        assert response.status_code == 503, response.text
    finally:
        with case.database.owner.begin() as db:
            db.execute(text("GRANT INSERT ON audit_logs TO aegis_app"))
    assert domain_counts(case) == before and current(admin, rule) == rule


@pytest.mark.parametrize(
    "change", ["revision_id", "self_signed_source", "predicate_false", "reason"]
)
def test_risk_and_alert_detail_require_original_persisted_revision_and_full_predicate_proof(
    case: Case, admin: Login, change: str
) -> None:
    rule = publish(admin, import_rule(admin))
    normalize_events(case, admin, [powershell("powershell -Command Get-Date")])
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 1
    record = alerts(case)[0]
    frozen = deepcopy(record.rule_snapshot)
    changes: dict[str, Any] = {}
    if change == "revision_id":
        frozen["revision_id"] = str(uuid4())
        changes["rule_snapshot"] = frozen
    elif change == "self_signed_source":
        source = definition(
            rule["id"], title="Forged critical alert", level="critical", tags=["attack.t1110"]
        )
        compiled = compile_rule(source)
        frozen = {
            **compiled.snapshot(),
            "revision_id": rule["revision_id"],
            "definition_yaml": source,
            "compiled": compiled.as_dict(),
            "deployment_version": 2,
        }
        changes.update(
            rule_snapshot=frozen,
            title=compiled.title,
            severity=compiled.severity,
            reason=evaluate(compiled, record.event_snapshot),
        )
    elif change == "predicate_false":
        evidence = deepcopy(record.event_snapshot)
        evidence["process"]["command_line"] = "powershell -Command Get-Service"
        digest = hashlib.sha256(canonical_json(evidence)).hexdigest()
        contributors = deepcopy(record.event_snapshots)
        for contributor in contributors:
            contributor.update(event_snapshot=evidence, event_sha256=digest)
        changes.update(event_snapshot=evidence, event_sha256=digest, event_snapshots=contributors)
    else:
        changes["reason"] = {**record.reason, "matched_selections": ["invented"]}
    # Only this generated database's owner can mutate committed alert proof columns.
    with Session(case.database.owner) as db:
        db.execute(update(Alert).where(Alert.id == record.id).values(**changes))
        db.commit()
    before = domain_counts(case)
    response = admin.client.post(
        f"/api/v1/alerts/{record.id}/risk/recalculate",
        json={},
        headers={**admin.authorization, "If-Match": f'"{record.version}"'},
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "risk_evidence_integrity_mismatch"
    response = admin.client.get(f"/api/v1/alerts/{record.id}", headers=admin.authorization)
    assert (
        response.status_code == 409
        and response.json()["code"] == "mitre_evidence_integrity_mismatch"
    )
    assert domain_counts(case) == before


@pytest.mark.parametrize("tags", [["attack.t9999"], ["attack.invalid"], ["attack.defense-evasion"]])
def test_unknown_sigma_attack_tags_cannot_enter_import_or_coverage(
    case: Case, admin: Login, tags: list[str]
) -> None:
    before = domain_counts(case)
    response = admin.client.post(
        BASE + "/rules", json={"yaml": definition(tags=tags)}, headers=admin.authorization
    )
    assert response.status_code == 422 and response.json()["code"] == "sigma_mitre_tag"
    assert domain_counts(case) == before


def test_repeated_distinct_sigma_alerts_cannot_invent_independent_or_event_bonuses(
    case: Case, admin: Login
) -> None:
    from .test_incidents import create

    publish(admin, import_rule(admin, definition(level="critical")))
    publish(
        admin,
        import_rule(admin, definition(level="critical", title="Second matching Sigma source")),
    )
    normalize_events(case, admin, [powershell("powershell -Command Get-Date") for _ in range(2)])
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 4
    records = alerts(case)
    assert len({row.event_id for row in records}) == 2
    incident = create(admin, alert_ids=[str(row.id) for row in records])
    assert incident["risk_score"] == 55
    explanation = incident["risk_explanation"]
    assert explanation["signal_units"] == []
    components = {item["code"]: item for item in explanation["components"]}
    assert components["D"]["points"] == 55
    assert components["C"]["points"] == components["E"]["points"] == 0
    assert components["C"]["status"] == components["E"]["status"] == "unknown"
    assert all(components[code]["status"] == "unknown" for code in "A U I T H P".split())
