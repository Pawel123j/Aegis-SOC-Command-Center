"""Opt-in IOC priority context around the unchanged version-three behaviour engine."""

import hashlib
from copy import deepcopy
from datetime import datetime
from typing import Any

from app.modules.ingestion.schemas import canonical_json
from app.modules.risk import engine as v3
from app.modules.risk.schemas import ContextFact, RiskInput, RiskResult, SeverityBaseline, Signal

POLICY_VERSION = "risk-policy-v4"
INTELLIGENCE_SEVERITY_SUFFIX = ":intelligence-severity"
POLICY: dict[str, Any] = {
    **deepcopy(v3.POLICY),
    "version": POLICY_VERSION,
    "production_default_policy_version": v3.POLICY_VERSION,
    "fallback_policy_hash": v3.POLICY_HASH,
    "policy_selection": "Use v4 for IOC context, a known IOC context or verified TI severity "
    "baseline; otherwise production retains unchanged risk-policy-v3.",
    "production_unknown_contexts": [kind for kind in v3.CONTEXTS if kind != "ioc_reputation"],
    "conditional_unknown_contexts": ["ioc_reputation"],
    "ioc_thresholds": {"suspicious": [50, 8], "malicious": [80, 15]},
    "ioc_below_threshold_points": {"malicious": 5, "suspicious": 0, "clean": 0, "unknown": 0},
    "ioc_missing_confidence_points": {"malicious": 5, "suspicious": 0, "clean": 0, "unknown": 0},
    "ioc_eligibility": "Only active, unexpired versioned facts whose entire supporting event "
    "set is qualifying signal/TI/Sigma proof and whose subject key matches when supplied. "
    "Expiry is tested strictly after max(first qualifying event time, provenance.as_of). "
    "Maximum I is 15; duplicate facts are never summed. "
    "Source scope is verified by the input builder.",
    "intelligence": "Verified immutable local IOC revision plus original typed event match; "
    "fixed medium severity contributes D30 only with unknown detection confidence. "
    "TI alone contributes no controlled behaviour family, "
    "independent-unit or qualified-event bonus. "
    "IOC reputation is a separate I component and does not confirm an attack.",
    "eligibility": "Unchanged v3 controlled builtin and Sigma proof, plus verified persisted "
    "TI match severity and versioned IOC context. Behavioural arithmetic remains v3.",
    "empty": "No qualifying behaviour or verified Sigma/TI severity proof => "
    "all components not_applicable and score0, even when an IOC context exists.",
}
POLICY_HASH = hashlib.sha256(canonical_json(POLICY)).hexdigest()


def policy_view() -> dict[str, Any]:
    return {**deepcopy(POLICY), "hash": POLICY_HASH}


def uses_intelligence(data: RiskInput) -> bool:
    return (
        "ioc_reputation" in data.known_contexts
        or any(fact.kind == "ioc_reputation" for fact in data.contexts)
        or any(item.id.endswith(INTELLIGENCE_SEVERITY_SUFFIX) for item in data.severity_baselines)
    )


def _ioc_points(fact: ContextFact, data: RiskInput, start: datetime) -> int:
    cutoff = max(start, fact.provenance.as_of)
    if (
        not fact.active
        or (fact.expires_at is not None and fact.expires_at <= cutoff)
        or (fact.subject_key is not None and fact.subject_key not in data.subject_keys)
    ):
        return 0
    if fact.value == "malicious":
        return 15 if fact.confidence is not None and fact.confidence >= 80 else 5
    if fact.value == "suspicious":
        return 8 if fact.confidence is not None and fact.confidence >= 50 else 0
    return 0


def calculate(data: RiskInput) -> RiskResult:
    intelligence = [
        item for item in data.severity_baselines if item.id.endswith(INTELLIGENCE_SEVERITY_SUFFIX)
    ]
    if any(item.severity != "medium" for item in intelligence):
        raise ValueError("intelligence severity must be medium")
    result = v3.calculate(data)
    if not uses_intelligence(data):
        return result
    sources: list[Signal | SeverityBaseline] = [*data.signals, *data.severity_baselines]
    qualifying_ids = {identifier for item in sources for identifier in item.evidence_ids}
    if not qualifying_ids:
        return result
    start = min(item.timestamp for item in data.evidence if item.id in qualifying_ids)
    component = next(item for item in result.components if item.code == "I")
    facts = sorted(
        (
            fact
            for fact in data.contexts
            if fact.kind == "ioc_reputation" and set(fact.evidence_ids) <= qualifying_ids
        ),
        key=lambda fact: canonical_json(fact.model_dump(mode="json")),
    )
    scored = [(_ioc_points(fact, data, start), fact) for fact in facts]
    component.points = max((points for points, _ in scored), default=0)
    component.evidence_ids = sorted(
        {
            identifier
            for points, fact in scored
            if points == component.points and points > 0
            for identifier in fact.evidence_ids
        }
    )
    component.details = {
        "facts": [{"points": points, **fact.model_dump(mode="json")} for points, fact in scored]
    }
    if component.status == "unknown":
        component.reason = (
            "Kontekst reputacji IOC nie jest dostępny; zero punktów nie potwierdza bezpieczeństwa."
        )
    elif component.points:
        component.reason = (
            "Maksimum z kwalifikującego się, wersjonowanego kontekstu IOC; "
            "wartości nie sumują się. Malicious z confidence co najmniej 80 daje 15 punktów, "
            "niższe lub nieznane confidence daje 5; suspicious z confidence co najmniej 50 "
            "daje 8. To priorytet oceny, nie dowód ataku."
        )
    else:
        component.reason = (
            "Dostępny kontekst IOC jest clean/unknown lub nie spełnia warunków punktowania."
        )
    if intelligence:
        identifiers = {item.id for item in intelligence}
        detection = next(item for item in result.components if item.code == "D")
        if detection.details.get("winner_signal_id") in identifiers:
            detection.reason = (
                "Bazowe 30 punktów medium z zachowanego dopasowania IOC TI; "
                "bez potwierdzonej rodziny zachowania i bez znanego confidence wykrycia."
            )
        if not data.signals:
            has_sigma = len(intelligence) != len(data.severity_baselines)
            reason = (
                "Bazowe detekcje TI i Sigma nie ustanawiają kontrolowanej rodziny zachowania; "
                if has_sigma
                else "Dopasowanie IOC TI nie ustanawia kontrolowanej rodziny zachowania; "
            ) + "brak niezależnych sygnałów i premii za liczbę zdarzeń."
            for item in result.components:
                if item.code in {"C", "E"}:
                    item.reason = reason
    raw = sum(item.points for item in result.components)
    result.raw_score = raw
    result.score = min(100, raw)
    result.clipping = result.score - raw
    result.level = v3.risk_level(result.score)
    return result
