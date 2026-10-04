"""Real immutable import, versioned detection, scoped candidate tags and priority."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.modules.correlation.builtin import BUILTIN_RULES as CORRELATION_RULES
from app.modules.correlation.models import CorrelationJob, CorrelationScope
from app.modules.correlation.processing import process_once as correlate_once
from app.modules.detections.models import DetectionJob
from app.modules.ingestion.schemas import canonical_json
from app.modules.risk.models import RiskCalculation
from app.modules.sigma.compiler import EVALUATOR_VERSION, compile_rule
from app.modules.sigma.models import SigmaRule, SigmaRuleVersion

from .helper_correlation import auth_sequence, normalize_inputs, seal
from .helper_ingestion import processing_database
from .helper_sigma import definition, document, domain_counts, import_rule, publish
from .helpers import Case, Login, migrate
from .test_incidents import create
from .test_initial_alerts import alerts, detect_once, normalize_events, powershell, user

pytestmark = pytest.mark.integration


def view(principal: Login, identifier: str) -> dict[str, Any]:
    response = principal.client.get(
        f"/api/v1/sigma/rules/{identifier}", headers=principal.authorization
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


def detail(principal: Login, identifier: UUID) -> dict[str, Any]:
    response = principal.client.get(f"/api/v1/alerts/{identifier}", headers=principal.authorization)
    assert response.status_code == 200, response.text
    return dict(response.json())


def test_validate_and_pure_test_have_no_storage_effects(case: Case, admin: Login) -> None:
    source = definition()
    identities = normalize_events(case, admin, [powershell("powershell -Command Get-Date")])
    before = domain_counts(case)
    validated = admin.client.post(
        "/api/v1/sigma/validate", json={"yaml": source}, headers=admin.authorization
    )
    assert validated.status_code == 200 and validated.json()["valid"] is True
    test = admin.client.post(
        "/api/v1/sigma/test",
        json={"yaml": source, "events": [document(case, identities[0])]},
        headers=admin.authorization,
    )
    assert test.status_code == 200, test.text
    assert test.json()["tested_events"] == 1 and test.json()["matches"][0]["event_id"] == str(
        identities[0]
    )
    assert domain_counts(case) == before


def test_import_is_disabled_idempotent_and_new_source_requires_explicit_revision(
    case: Case, admin: Login
) -> None:
    source = definition(description="Reviewed source")
    rule = import_rule(admin, source)
    assert rule["revision"] == rule["version"] == 1 and rule["enabled"] is False
    assert rule["definition_yaml"] == source
    assert rule["source_sha256"] == hashlib.sha256(source.encode()).hexdigest()
    assert rule["compiled_sha256"] == hashlib.sha256(canonical_json(rule["compiled"])).hexdigest()
    before = domain_counts(case)
    response = admin.client.post(
        "/api/v1/sigma/rules", json={"yaml": source}, headers=admin.authorization
    )
    assert response.status_code == 200 and response.json() == rule
    changed = admin.client.post(
        "/api/v1/sigma/rules",
        json={"yaml": definition(rule["id"], title="Changed")},
        headers=admin.authorization,
    )
    assert changed.status_code == 409 and changed.json()["code"] == "sigma_rule_exists"
    assert domain_counts(case) == before


def test_enabled_revision_emits_atomic_frozen_proof_and_survives_retry(
    case: Case, admin: Login
) -> None:
    rule = publish(admin, import_rule(admin))
    identities = normalize_events(case, admin, [powershell("powershell -Command Get-Date")])
    database = processing_database(case)
    assert detect_once(database, case.database.settings)["alerts"] == 1
    record = alerts(case)[0]
    assert record.rule_id == f"sigma:{rule['id']}" and record.rule_version == "1"
    assert record.evaluator_version == "sigma-subset-v1" and record.event_id == identities[0]
    response = detail(admin, record.id)
    assert response["detection_type"] == "sigma" and response["event_count"] == 1
    assert response["rule_snapshot"]["definition_yaml"] == rule["definition_yaml"]
    assert response["rule_snapshot"]["revision_id"] == rule["revision_id"]
    assert response["rule_snapshot"]["deployment_version"] == 2
    assert (
        response["risk_score"] == 45
        and response["risk_explanation"]["policy_version"] == "risk-policy-v3"
    )
    components = {item["code"]: item for item in response["risk_explanation"]["components"]}
    assert components["D"]["points"] == 45
    assert components["C"]["status"] == components["E"]["status"] == "unknown"
    assert all(components[code]["status"] == "unknown" for code in "A U I T H P".split())
    assert response["mitre_mapping"]["claim"] == "candidate_association"
    assert response["mitre_mapping"]["confirmed_attack"] is False
    before = domain_counts(case)
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 0
    assert domain_counts(case) == before
    assert before["incidents"] == 1 and before["risk_calculations"] == 2
    with Session(case.database.runtime) as db:
        job = db.get(DetectionJob, identities[0])
        assert job and {item["id"] for item in job.evaluated_rules} >= {record.rule_id}


def test_disabled_and_later_enabled_rule_never_reprocesses_checkpointed_event(
    case: Case, admin: Login
) -> None:
    rule = import_rule(admin)
    normalize_events(case, admin, [powershell("powershell -Command Get-Date")])
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 0
    publish(admin, rule)
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 0
    normalize_events(case, admin, [powershell("powershell -Command Get-Date")])
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 1


def test_new_revision_disables_and_preserves_existing_alert_and_risk_bytes(
    case: Case, admin: Login
) -> None:
    rule = publish(admin, import_rule(admin))
    normalize_events(case, admin, [powershell("powershell -Command Get-Date")])
    detect_once(processing_database(case), case.database.settings)
    record = alerts(case)[0]
    prior = detail(admin, record.id)
    changed = definition(
        rule["id"], title="New reviewed title", level="critical", description="Second"
    )
    response = admin.client.post(
        f"/api/v1/sigma/rules/{rule['id']}/versions",
        json={"yaml": changed},
        headers={**admin.authorization, "If-Match": '"2"'},
    )
    assert response.status_code == 201, response.text
    new = response.json()
    assert new["revision"] == 2 and new["version"] == 3 and new["enabled"] is False
    assert [item["revision"] for item in new["versions"]] == [2, 1]
    assert detail(admin, record.id) == prior
    publish(admin, new)
    normalize_events(case, admin, [powershell("powershell -Command Get-Date")])
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 1
    latest = next(item for item in alerts(case) if item.id != record.id)
    assert latest.rule_version == "2" and latest.severity == "critical" and latest.risk_score == 55
    assert detail(admin, record.id) == prior


@pytest.mark.parametrize("operation", ["publish", "revision"])
@pytest.mark.parametrize(
    "header,status,code", [(None, 428, "version_required"), ('"99"', 412, "version_conflict")]
)
def test_version_mutations_require_current_etag(
    case: Case, admin: Login, operation: str, header: str | None, status: int, code: str
) -> None:
    rule = import_rule(admin)
    before = domain_counts(case)
    headers = {**admin.authorization, **({"If-Match": header} if header else {})}
    route = f"/api/v1/sigma/rules/{rule['id']}"
    response = (
        admin.client.patch(route, json={"enabled": True}, headers=headers)
        if operation == "publish"
        else admin.client.post(
            route + "/versions",
            json={"yaml": definition(rule["id"], title="Changed")},
            headers=headers,
        )
    )
    assert response.status_code == status and response.json()["code"] == code
    assert domain_counts(case) == before


@pytest.mark.parametrize(
    "change,code", [("identity", "sigma_id_mismatch"), ("same", "sigma_definition_unchanged")]
)
def test_revision_identity_and_actual_change_are_checked(
    case: Case, admin: Login, change: str, code: str
) -> None:
    rule = import_rule(admin)
    source = definition() if change == "identity" else rule["definition_yaml"]
    before = domain_counts(case)
    response = admin.client.post(
        f"/api/v1/sigma/rules/{rule['id']}/versions",
        json={"yaml": source},
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert response.status_code == 409 and response.json()["code"] == code
    assert domain_counts(case) == before


def test_concurrent_same_source_import_creates_one_identity_revision_and_audit(
    case: Case, admin: Login
) -> None:
    other = user(case, admin, "soc_manager")
    source = definition()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                principal.client.post,
                "/api/v1/sigma/rules",
                json={"yaml": source},
                headers=principal.authorization,
            )
            for principal in (admin, other)
        ]
        responses = [future.result(timeout=15) for future in futures]
    assert sorted(item.status_code for item in responses) == [200, 201]
    assert responses[0].json()["revision_id"] == responses[1].json()["revision_id"]
    assert domain_counts(case)["sigma_rules"] == domain_counts(case)["sigma_rule_versions"] == 1


def test_sigma_and_builtin_same_event_do_not_inflate_independent_or_event_bonuses(
    case: Case, admin: Login
) -> None:
    source = definition(
        level="critical",
        detection={
            "selection": {"CommandLine|contains": "-EncodedCommand"},
            "condition": "selection",
        },
    )
    publish(admin, import_rule(admin, source))
    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    records = alerts(case)
    assert len(records) == 2 and len({record.event_id for record in records}) == 1
    incident = create(admin, alert_ids=[str(record.id) for record in records])
    assert incident["risk_score"] == 55
    components = {item["code"]: item for item in incident["risk_explanation"]["components"]}
    assert components["C"]["points"] == components["E"]["points"] == 0
    assert components["T"]["status"] == "unknown"
    sigma = next(record for record in records if record.rule_id.startswith("sigma:"))
    response = admin.client.patch(
        f"/api/v1/alerts/{sigma.id}",
        json={"status": "false_positive"},
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert response.status_code == 200, response.text
    current = admin.client.get(
        f"/api/v1/incidents/{incident['id']}", headers=admin.authorization
    ).json()
    assert (
        current["risk_score"] == 45
        and current["mitre_mapping"]["excluded_false_positive_alerts"] == 1
    )


def test_sigma_replay_scope_and_live_coverage_are_separate(case: Case, admin: Login) -> None:
    publish(admin, import_rule(admin))
    scope = (uuid4(), uuid4())
    _, identities = normalize_inputs(
        case, admin, [powershell("powershell -Command Get-Date")], replay=scope
    )
    detect_once(processing_database(case), case.database.settings)
    record = alerts(case)[0]
    assert record.mode == "replay" and record.dataset_id == scope[0] and record.run_id == scope[1]
    assert record.event_id == identities[0]
    for mode, extra, observed in [
        ("live", {}, 0),
        ("replay", {"dataset_id": str(scope[0]), "run_id": str(scope[1])}, 1),
    ]:
        response = admin.client.get(
            "/api/v1/mitre/coverage",
            headers=admin.authorization,
            params={
                "mode": mode,
                "from": "2026-10-01T00:00:00Z",
                "to": "2026-10-02T00:00:00Z",
                **extra,
            },
        )
        assert response.status_code == 200, response.text
        row = next(item for item in response.json()["techniques"] if item["id"] == "T1059.001")
        assert row["alert_count"] == row["incident_count"] == observed
        assert row["configured_rule_count"] == row["enabled_rule_count"] == 4


def test_enabled_sigma_preserves_frozen_correlation_replay_manifest(
    case: Case, admin: Login
) -> None:
    rule = publish(
        admin,
        import_rule(
            admin,
            definition(
                level="medium",
                logsource={"product": "aegis", "service": "generic_json"},
                detection={
                    "selection": {"event.category": "authentication"},
                    "condition": "selection",
                },
            ),
        ),
    )
    scope = (uuid4(), uuid4())
    normalize_inputs(
        case, admin, auth_sequence(datetime(2026, 10, 1, 12, tzinfo=UTC)), replay=scope
    )
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 6
    sealed = seal(admin, scope, 6)
    namespace = f"replay:{scope[0]}:{scope[1]}"
    with Session(case.database.runtime) as db:
        snapshot = db.get(CorrelationScope, namespace)
        assert snapshot is not None
        original = deepcopy(snapshot.deployment_snapshot)
        assert {item["id"] for item in original} == {item.id for item in CORRELATION_RULES}
        checkpoints = list(db.scalars(select(DetectionJob)))
        assert len(checkpoints) == 6
        assert all(
            any(item["id"] == f"sigma:{rule['id']}" for item in job.evaluated_rules)
            for job in checkpoints
        )
    assert correlate_once(processing_database(case), case.database.settings)["alerts"] == 2
    assert len(alerts(case)) == 8 and seal(admin, scope, 6) == sealed
    with Session(case.database.runtime) as db:
        snapshot = db.get(CorrelationScope, namespace)
        assert snapshot is not None and snapshot.deployment_snapshot == original
        jobs = list(db.scalars(select(CorrelationJob)))
        assert len(jobs) == 6 and all(job.state == "processed" for job in jobs)
        assert all(
            {item["id"] for item in job.evaluated_rules} == {item.id for item in CORRELATION_RULES}
            for job in jobs
        )


def test_import_and_detection_audit_failures_roll_back_entire_transaction(
    case: Case, admin: Login
) -> None:
    source = definition()
    before = domain_counts(case)
    with case.database.owner.begin() as db:
        db.execute(text("REVOKE INSERT ON audit_logs FROM aegis_app"))
    try:
        response = admin.client.post(
            "/api/v1/sigma/rules", json={"yaml": source}, headers=admin.authorization
        )
        assert response.status_code == 503, response.text
    finally:
        with case.database.owner.begin() as db:
            db.execute(text("GRANT INSERT ON audit_logs TO aegis_app"))
    assert domain_counts(case) == before
    publish(admin, import_rule(admin, source))
    normalize_events(case, admin, [powershell("powershell -Command Get-Date")])
    # Enqueue is durable independently, but alert/risk/mapping/case are one transaction.
    from app.modules.detections.processing import enqueue_normalized

    enqueue_normalized(processing_database(case), 100)
    before = domain_counts(case)
    with case.database.owner.begin() as db:
        db.execute(text("REVOKE INSERT ON alert_mitre_snapshots FROM aegis_app"))
    try:
        with pytest.raises(DBAPIError):
            detect_once(processing_database(case), case.database.settings)
    finally:
        with case.database.owner.begin() as db:
            db.execute(text("GRANT INSERT ON alert_mitre_snapshots TO aegis_app"))
    assert domain_counts(case) == before
    with Session(case.database.runtime) as db:
        assert db.scalar(select(DetectionJob.state)) == "pending"
    assert detect_once(processing_database(case), case.database.settings)["alerts"] == 1


def test_downgrade_refuses_nonempty_sigma_identity_and_preserves_source(
    case: Case, admin: Login
) -> None:
    rule = import_rule(admin)
    before = domain_counts(case)
    with pytest.raises(DBAPIError) as rejected:
        migrate(case.database.owner, "0008_mitre", downgrade=True)
    assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
    assert domain_counts(case) == before and view(admin, rule["id"]) == rule
    with case.database.runtime.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "0009_sigma"


def test_nonempty_v2_history_survives_sigma_upgrade_and_only_explicit_recalc_creates_v3(
    case: Case, admin: Login
) -> None:
    normalize_events(case, admin, [powershell()])
    detect_once(processing_database(case), case.database.settings)
    record = alerts(case)[0]
    # Reproduce a pre-Sigma row from a real builtin proof. The v2 policy hash is
    # fixed from the previous release; v2 inputs had no severity_baselines key.
    with Session(case.database.owner) as db:
        row = db.get(RiskCalculation, record.risk_calculation_id)
        assert row is not None
        snapshot = deepcopy(row.input_snapshot)
        snapshot["scoring_input"].pop("severity_baselines")
        row.policy_version = "risk-policy-v2"
        row.policy_hash = "fe87d0dd228f33d01ce32434cd8ac6620f4cf1d3723ebd077ca2add7b466e85c"
        row.input_snapshot = snapshot
        row.input_sha256 = hashlib.sha256(canonical_json(snapshot)).hexdigest()
        db.commit()
    migrate(case.database.owner, "0008_mitre", downgrade=True)
    before = detail(admin, record.id)
    first = admin.client.get(f"/api/v1/alerts/{record.id}/risk", headers=admin.authorization)
    assert first.status_code == 200
    old = first.json()
    assert old["current"]["policy_version"] == "risk-policy-v2"
    migrate(case.database.owner)
    assert detail(admin, record.id) == before
    for _ in range(2):
        response = admin.client.get(f"/api/v1/alerts/{record.id}/risk", headers=admin.authorization)
        assert response.status_code == 200 and response.json() == old
    recalc = admin.client.post(
        f"/api/v1/alerts/{record.id}/risk/recalculate",
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert recalc.status_code == 200, recalc.text
    changed = recalc.json()
    assert changed["current"]["policy_version"] == "risk-policy-v3"
    assert changed["current"]["score"] == old["current"]["score"] == 45
    assert len(changed["history"]) == 2 and changed["history"][1] == old["history"][0]
    assert changed["current"]["previous_id"] == old["current"]["id"]


def seed_revision(db: Session, identity: UUID, revision: int, actor: UUID) -> None:
    source = definition(identity, title=f"Own authored revision {revision}")
    compiled = compile_rule(source)
    db.add(
        SigmaRuleVersion(
            rule_id=identity,
            revision=revision,
            definition_yaml=source,
            source_sha256=compiled.source_sha256,
            compiled_sha256=compiled.compiled_sha256,
            compiled=compiled.as_dict(),
            evaluator_version=EVALUATOR_VERSION,
            created_by=actor,
        )
    )
    db.flush()
    db.execute(
        text("SELECT public.aegis_select_sigma_revision(:rule,:revision,:actor)"),
        {"rule": identity, "revision": revision, "actor": actor},
    )


def test_catalog_limit_uses_total_disabled_and_enabled_identities(case: Case, admin: Login) -> None:
    actor = UUID(admin.user_id)
    with Session(case.database.owner) as db:
        for _ in range(100):
            identity = uuid4()
            db.add(SigmaRule(id=identity, detection_id=f"sigma:{identity}", created_by=actor))
            db.flush()
            seed_revision(db, identity, 1, actor)
        db.commit()
    before = domain_counts(case)
    response = admin.client.post(
        "/api/v1/sigma/rules", json={"yaml": definition()}, headers=admin.authorization
    )
    assert response.status_code == 409 and response.json()["code"] == "sigma_rule_limit"
    listed = admin.client.get("/api/v1/sigma/rules", headers=admin.authorization)
    assert listed.status_code == 200 and len(listed.json()["items"]) == 100
    assert all(item["enabled"] is False for item in listed.json()["items"])
    assert domain_counts(case) == before


def test_immutable_history_bound_is_enforced_by_api_and_storage(case: Case, admin: Login) -> None:
    rule = import_rule(admin)
    identity, actor = UUID(rule["id"]), UUID(admin.user_id)
    with Session(case.database.owner) as db:
        for revision in range(2, 21):
            seed_revision(db, identity, revision, actor)
        db.commit()
    current = view(admin, rule["id"])
    assert current["revision"] == current["version"] == 20 and len(current["versions"]) == 20
    before = domain_counts(case)
    response = admin.client.post(
        f"/api/v1/sigma/rules/{rule['id']}/versions",
        json={"yaml": definition(identity, title="Twenty first")},
        headers={**admin.authorization, "If-Match": '"20"'},
    )
    assert response.status_code == 409 and response.json()["code"] == "sigma_revision_limit"
    with Session(case.database.runtime) as db:
        compiled = compile_rule(definition(identity, title="Twenty first"))
        db.add(
            SigmaRuleVersion(
                rule_id=identity,
                revision=21,
                definition_yaml=definition(identity, title="Twenty first"),
                source_sha256=compiled.source_sha256,
                compiled_sha256=compiled.compiled_sha256,
                compiled=compiled.as_dict(),
                evaluator_version=EVALUATOR_VERSION,
                created_by=actor,
            )
        )
        with pytest.raises(DBAPIError) as rejected:
            db.flush()
        assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
        db.rollback()
    assert domain_counts(case) == before


@pytest.mark.parametrize(
    "field",
    ["definition_yaml", "source_sha256", "compiled_sha256", "compiled", "evaluator_version"],
)
def test_corrupt_selected_revision_fails_closed_and_never_checkpoints(
    case: Case, admin: Login, field: str
) -> None:
    rule = publish(admin, import_rule(admin))
    normalize_events(case, admin, [powershell("powershell -Command Get-Date")])
    changes: dict[str, Any] = {
        "definition_yaml": "{}",
        "source_sha256": "a" * 64,
        "compiled_sha256": "b" * 64,
        "compiled": {},
        "evaluator_version": "unknown-v1",
    }
    with Session(case.database.owner) as db:
        db.execute(
            update(SigmaRuleVersion)
            .where(SigmaRuleVersion.id == UUID(rule["revision_id"]))
            .values({field: changes[field]})
        )
        db.commit()
    from app.modules.detections.processing import RuleConfigurationError

    with pytest.raises(RuleConfigurationError, match="sigma_configuration_mismatch"):
        detect_once(processing_database(case), case.database.settings)
    assert alerts(case) == []
    with Session(case.database.runtime) as db:
        assert db.scalar(select(DetectionJob.state)) == "pending"
    response = admin.client.get(f"/api/v1/sigma/rules/{rule['id']}", headers=admin.authorization)
    assert response.status_code == 503 and response.json()["code"] == "sigma_revision_unavailable"
