"""Production assessments only admit controlled predicates and original verified proof."""

import hashlib
from typing import Any, Literal, cast
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.modules.alerts.evidence import verified_events
from app.modules.alerts.models import Alert
from app.modules.correlation.builtin import BUILTIN_RULES as CORRELATION_RULES
from app.modules.correlation.contracts import EVALUATOR_VERSION as CORRELATION_EVALUATOR
from app.modules.correlation.engine import condition_matches, entity_keys, evaluate_anchor
from app.modules.detections.builtin import BUILTIN_RULES, EVALUATOR_VERSION, evaluate_rule
from app.modules.ingestion.schemas import canonical_json
from app.modules.intelligence.contracts import EVALUATOR_VERSION as INTELLIGENCE_EVALUATOR
from app.modules.intelligence.matching import risk_contexts
from app.modules.intelligence.matching import verified_alert as verified_intelligence_alert
from app.modules.normalization.schemas import NormalizedSecurityEvent
from app.modules.risk.schemas import EvidenceReference, Family, RiskInput, SeverityBaseline, Signal
from app.modules.sigma.compiler import EVALUATOR_VERSION as SIGMA_EVALUATOR
from app.modules.sigma.service import verified_alert

SINGLE_FAMILIES: dict[str, Family] = {
    "powershell-suspicious-command": "suspicious_execution",
    "linux-root-session": "privilege_change",
    "windows-local-admin-member-added": "privilege_change",
}
STAGE_FAMILIES: dict[str, Family] = {
    "failed_logins": "authentication_attack",
    "successful_login": "authentication_attack",
    "powershell_started": "suspicious_execution",
    "outbound_connection": "suspicious_execution",
    "administrator_group_change": "privilege_change",
}


def _signals(alert: Alert, events: list[NormalizedSecurityEvent]) -> list[Signal]:
    groups: dict[Family, set[UUID]] = {}
    if alert.evaluator_version == EVALUATOR_VERSION:
        if len(events) != 1:
            raise ValueError("single-event rule requires exactly one proof event")
        rule = next((item for item in BUILTIN_RULES if item.id == alert.rule_id), None)
        if (
            rule is None
            or rule.version != alert.rule_version
            or rule.severity != alert.severity
            or alert.rule_snapshot != rule.snapshot()
            or not evaluate_rule(alert.rule_id, alert.event_snapshot)
        ):
            raise ValueError("untrusted risk rule predicate")
        groups[SINGLE_FAMILIES[rule.id]] = {event.event_id for event in events}
    elif alert.evaluator_version == CORRELATION_EVALUATOR:
        correlation = next((item for item in CORRELATION_RULES if item.id == alert.rule_id), None)
        frozen = {
            key: value for key, value in alert.rule_snapshot.items() if key != "deployment_version"
        }
        if (
            correlation is None
            or correlation.version != alert.rule_version
            or correlation.severity != alert.severity
            or frozen != correlation.snapshot()
        ):
            raise ValueError("untrusted risk rule predicate")
        anchor = next(event for event in events if event.event_id == alert.event_id)
        match = evaluate_anchor(correlation, anchor, events)
        if match is None or match["event_ids"] != [str(event.event_id) for event in events]:
            raise ValueError("risk correlation predicate failed")
        stages = alert.reason["stages"]
        if len(stages) != len(correlation.pattern.stages):
            raise ValueError("risk stage integrity failed")
        by_id = {str(event.event_id): event for event in events}
        for stage, proof in zip(correlation.pattern.stages, stages, strict=True):
            identities = proof["event_ids"]
            if (
                proof["name"] != stage.name
                or len(identities) != stage.count
                or any(
                    not condition_matches(stage.condition, by_id[identity].model_dump(mode="json"))
                    for identity in identities
                )
            ):
                raise ValueError("risk stage predicate failed")
            family = (
                "privilege_change"
                if correlation.id == "login_then_local_admin_change"
                else STAGE_FAMILIES[stage.name]
            )
            groups.setdefault(family, set()).update(UUID(identity) for identity in identities)
    else:
        raise ValueError("unsupported risk evaluator")
    return [
        Signal(
            id=f"{alert.id}:{family}",
            family=family,
            severity=alert.severity,
            evidence_ids=sorted(identities),
            alert_ids=[alert.id],
        )
        for family, identities in sorted(groups.items())
    ]


def build_input(
    alerts: list[Alert],
    *,
    subject_id: UUID,
    mode: str,
    dataset_id: UUID | None,
    run_id: UUID,
    exclude_false_positive: bool,
    db: Session | None = None,
) -> tuple[RiskInput, dict[str, Any]]:
    references: dict[UUID, EvidenceReference] = {}
    source_events: dict[UUID, NormalizedSecurityEvent] = {}
    signals: list[Signal] = []
    baselines: list[SeverityBaseline] = []
    sources = []
    keys: set[str] = set()
    excluded = []
    try:
        for alert in sorted(alerts, key=lambda item: item.id):
            if (
                alert.mode != mode
                or alert.run_id != run_id
                or (mode == "replay" and alert.dataset_id != dataset_id)
            ):
                raise ValueError("risk subject scope mismatch")
            events = verified_events(alert)
            source: dict[str, Any] = {
                "id": str(alert.id),
                "event_sha256": alert.event_sha256,
                "rule_id": alert.rule_id,
                "rule_version": alert.rule_version,
                "evaluator_version": alert.evaluator_version,
                "severity": alert.severity,
            }
            if exclude_false_positive:
                source["excluded"] = alert.status == "false_positive"
            sources.append(source)
            if exclude_false_positive and alert.status == "false_positive":
                excluded.append(str(alert.id))
                continue
            if alert.evaluator_version == SIGMA_EVALUATOR:
                if db is None or len(events) != 1:
                    raise ValueError("Sigma requires immutable persisted revision proof")
                verified_alert(db, alert)
                baselines.append(
                    SeverityBaseline(
                        id=f"{alert.id}:sigma-severity",
                        severity=cast(
                            Literal["informational", "low", "medium", "high", "critical"],
                            alert.severity,
                        ),
                        evidence_ids=[events[0].event_id],
                        alert_ids=[alert.id],
                    )
                )
                source["sigma_revision_id"] = alert.rule_snapshot["revision_id"]
                source["sigma_source_sha256"] = alert.rule_snapshot["source_sha256"]
                source["sigma_compiled_sha256"] = alert.rule_snapshot["compiled_sha256"]
            elif alert.evaluator_version == INTELLIGENCE_EVALUATOR:
                if db is None or len(events) != 1:
                    raise ValueError("Intelligence requires immutable persisted match proof")
                verified_intelligence_alert(db, alert)
                baselines.append(
                    SeverityBaseline(
                        id=f"{alert.id}:intelligence-severity",
                        severity="medium",
                        evidence_ids=[events[0].event_id],
                        alert_ids=[alert.id],
                    )
                )
                source["intelligence_proof_sha256"] = alert.reason["proof_sha256"]
            else:
                signals.extend(_signals(alert, events))
            for event in events:
                reference = EvidenceReference(
                    id=event.event_id,
                    timestamp=event.timestamp,
                    sha256=hashlib.sha256(
                        canonical_json(event.model_dump(mode="json"))
                    ).hexdigest(),
                )
                if reference.id in references and references[reference.id] != reference:
                    raise ValueError("conflicting event proof")
                references[reference.id] = reference
                source_events[event.event_id] = event
                keys.update(value for value in entity_keys(event).values() if value is not None)
        contexts, intelligence_metadata = (
            risk_contexts(db, source_events) if db is not None else ([], {})
        )
        data = RiskInput(
            evidence=sorted(references.values(), key=lambda item: item.id),
            signals=signals,
            severity_baselines=baselines,
            contexts=contexts,
            subject_keys=sorted(keys),
            subject_id=subject_id,
            mode=cast(Literal["live", "replay"], mode),
            dataset_id=dataset_id if mode == "replay" else None,
            run_id=run_id,
        )
    except (KeyError, TypeError, ValueError):
        raise ApiError(
            409,
            "risk_evidence_integrity_mismatch",
            "Risk requires verified, supported immutable evidence",
        ) from None
    snapshot = {
        "scoring_input": data.model_dump(mode="json"),
        "source_alerts": sources,
        "excluded_alert_ids": excluded,
        "context_origin": "unavailable-production-context"
        if mode == "live"
        else "unknown-context-as-of-replay",
    }
    if contexts:
        snapshot["context_origin"] = "frozen-local-ioc-at-first-evaluation"
        snapshot["intelligence_selection"] = intelligence_metadata
    return data, snapshot
