"""Pure integer priority policy; unknown context never becomes an asserted fact."""

import hashlib
from copy import deepcopy
from datetime import timedelta
from typing import Any, Literal
from uuid import UUID

from app.modules.ingestion.schemas import canonical_json
from app.modules.risk.schemas import (
    ContextFact,
    RiskComponent,
    RiskInput,
    RiskLevel,
    RiskResult,
    Signal,
    SignalUnit,
)

POLICY_VERSION = "risk-policy-v2"
SEVERITY_POINTS = {"informational": 5, "low": 15, "medium": 30, "high": 45, "critical": 55}
CONTEXTS = (
    "host_criticality",
    "user_importance",
    "ioc_reputation",
    "attack_tactics",
    "confirmed_history",
    "prior_privileges",
)
COMPONENTS = (
    ("D", "Siła wykrytego zachowania", 55),
    ("C", "Niezależne sygnały", 9),
    ("E", "Liczba zdarzeń dowodowych", 12),
    ("A", "Krytyczność hosta", 15),
    ("U", "Znaczenie konta", 10),
    ("I", "Reputacja IOC", 15),
    ("T", "Potwierdzone taktyki", 6),
    ("H", "Potwierdzona wcześniejsza historia", 5),
    ("P", "Wcześniejsze uprawnienia", 5),
)
POLICY: dict[str, Any] = {
    "version": POLICY_VERSION,
    "level_thresholds": {
        "low": [0, 29],
        "medium": [30, 59],
        "high": [60, 79],
        "critical": [80, 100],
    },
    "severity_points": SEVERITY_POINTS,
    "components": [
        {"code": code, "label": label, "maximum": maximum} for code, label, maximum in COMPONENTS
    ],
    "production_unknown_contexts": list(CONTEXTS),
    "description": "Wynik określa priorytet oceny, nie prawdopodobieństwo ani potwierdzenie ataku. "
    "Brak kontekstu daje zero punktów i jawny status unknown.",
    "formula": "min(100,D+C+E+A+U+I+T+H+P)",
    "signal_policy": "controlled-builtin-v1; overlap connected components within family",
    "confidence_policy": "versioned provenance required; absent confidence uses "
    "severity baseline and remains unknown",
    "host_weights": {"low": 0, "medium": 5, "high": 10, "critical": 15},
    "user_weights": {"low": 0, "medium": 3, "high": 6, "critical": 10},
    "ioc_thresholds": {"suspicious": [50, 8], "malicious": [80, 15]},
    "privilege_weights": {"standard": 0, "privileged": 3, "administrator": 5},
    "correlation": "min(9,3*(independent_units-1))",
    "events": "min(12,2*(unique recognized signal proof events-1)); unrelated refs excluded",
    "tactics": "min(6,2*(min(distinct verified tactics,verified families)-1))",
    "history": "confirmed_malicious strong identity; previous30days; "
    "no current/alias/evidenceoverlap/samereplayrun/crossdataset",
    "eligibility": "controlled complete predicate proof; successful login alone not independent",
    "empty": "no recognized evidence => all components not_applicable and score0",
}
POLICY_HASH = hashlib.sha256(canonical_json(POLICY)).hexdigest()


def policy_view() -> dict[str, Any]:
    return {**deepcopy(POLICY), "hash": POLICY_HASH}


def risk_level(score: int) -> RiskLevel:
    return "low" if score < 30 else "medium" if score < 60 else "high" if score < 80 else "critical"


def _unique_signals(signals: list[Signal]) -> list[Signal]:
    by_id: dict[str, Signal] = {}
    for item in signals:
        previous = by_id.get(item.id)
        if previous is not None and previous.model_dump() != item.model_dump():
            raise ValueError("conflicting signal identity")
        by_id[item.id] = item
    return sorted(by_id.values(), key=lambda item: item.id)


def _units(signals: list[Signal]) -> list[SignalUnit]:
    result = []
    for family in sorted({item.family for item in signals}):
        remaining = [item for item in signals if item.family == family]
        while remaining:
            first = remaining.pop(0)
            events, alerts = set(first.evidence_ids), set(first.alert_ids)
            changed = True
            while changed:
                changed = False
                for candidate in remaining[:]:
                    if events.intersection(candidate.evidence_ids):
                        remaining.remove(candidate)
                        events.update(candidate.evidence_ids)
                        alerts.update(candidate.alert_ids)
                        changed = True
            result.append(
                SignalUnit(family=family, evidence_ids=sorted(events), alert_ids=sorted(alerts))
            )
    return sorted(
        result, key=lambda item: (item.family, [str(identity) for identity in item.evidence_ids])
    )


def _context_points(fact: ContextFact, data: RiskInput) -> int:
    qualifying_ids = {identity for signal in data.signals for identity in signal.evidence_ids}
    start = min(item.timestamp for item in data.evidence if item.id in qualifying_ids)
    if not _active_context(fact, start):
        return 0
    if fact.subject_key is not None and fact.subject_key not in data.subject_keys:
        return 0
    if fact.kind == "host_criticality":
        return int(POLICY["host_weights"][fact.value])
    if fact.kind == "user_importance":
        return int(POLICY["user_weights"][fact.value])
    if fact.kind == "ioc_reputation":
        threshold, points = POLICY["ioc_thresholds"].get(fact.value, [101, 0])
        return int(points) if fact.confidence is not None and fact.confidence >= threshold else 0
    if fact.kind == "prior_privileges":
        return (
            int(POLICY["privilege_weights"][fact.value])
            if fact.observed_at is not None
            and fact.observed_at < start
            and fact.provenance.as_of < start
            else 0
        )
    if fact.kind == "confirmed_history":
        assert fact.observed_at is not None
        excluded = {*data.excluded_incident_ids, data.subject_id}
        if (
            fact.prior_incident_id in excluded
            or not start - timedelta(days=30) <= fact.observed_at < start
            or fact.observed_at > fact.provenance.as_of
            or set(fact.prior_evidence_ids).intersection(item.id for item in data.evidence)
            or fact.prior_mode != data.mode
            or (
                data.mode == "replay"
                and (fact.prior_run_id == data.run_id or fact.prior_dataset_id != data.dataset_id)
            )
        ):
            return 0
        return 5
    return 0


def _active_context(fact: ContextFact, start: Any) -> bool:
    cutoff = max(start, fact.provenance.as_of)
    return fact.active and (fact.expires_at is None or fact.expires_at > cutoff)


def calculate(data: RiskInput) -> RiskResult:
    signals = _unique_signals(data.signals)
    units = _units(signals)
    evidence_ids = sorted({identity for signal in signals for identity in signal.evidence_ids})
    components = []
    confidence_values = {item.confidence is not None for item in signals}
    confidence_status: Literal["known", "unknown", "mixed", "not_applicable"] = (
        "not_applicable"
        if not signals
        else "mixed"
        if len(confidence_values) > 1
        else "known"
        if True in confidence_values
        else "unknown"
    )
    candidates = [
        (
            SEVERITY_POINTS[item.severity]
            if item.confidence is None
            else SEVERITY_POINTS[item.severity] * item.confidence // 100,
            item.id,
            item,
        )
        for item in signals
    ]
    winner = sorted(candidates, key=lambda item: (-item[0], item[1]))[0] if candidates else None
    base = {
        "D": winner[0] if winner else 0,
        "C": min(9, 3 * max(0, len(units) - 1)),
        "E": min(12, 2 * max(0, len(evidence_ids) - 1)),
    }
    codes = dict(zip(CONTEXTS, ("A", "U", "I", "T", "H", "P"), strict=True))
    missing = [
        name
        for name in CONTEXTS
        if name not in data.known_contexts and not any(fact.kind == name for fact in data.contexts)
    ]
    if confidence_status in {"unknown", "mixed"}:
        missing.append("detection_confidence")
    for code, label, maximum in COMPONENTS:
        status: Literal["known", "unknown", "not_applicable"]
        details: dict[str, Any] = {}
        cited: list[UUID] = []
        if not evidence_ids:
            points, status, reason = 0, "not_applicable", "Brak kwalifikujących się dowodów."
        elif code in base:
            points, status = base[code], "known"
            if code == "D":
                reason = (
                    "Maksimum punktów severity pomnożonych przez udokumentowane confidence."
                    if winner and winner[2].confidence is not None
                    else "Bazowe punkty severity; confidence pozostaje nieznane."
                    if winner
                    else "Brak rozpoznanego sygnału behawioralnego."
                )
                details = {
                    "winner_signal_id": winner[1] if winner else None,
                    "severity": winner[2].severity if winner else None,
                    "confidence": winner[2].confidence if winner else None,
                    "candidates": [
                        {
                            "signal_id": identity,
                            "points": value,
                            "severity": signal.severity,
                            "confidence": signal.confidence,
                        }
                        for value, identity, signal in sorted(candidates, key=lambda item: item[1])
                    ],
                }
                cited = sorted(set(winner[2].evidence_ids)) if winner else []
            else:
                reason = (
                    "Trzy punkty za każdą kolejną niezależną jednostkę; "
                    "nakładające się dowody tej samej rodziny liczą się raz."
                    if code == "C"
                    else "Dwa punkty za każde kolejne unikalne zdarzenie; maksimum 12."
                )
                details = (
                    {"independent_units": len(units)}
                    if code == "C"
                    else {"unique_events": len(evidence_ids)}
                )
                cited = evidence_ids
        else:
            kind = next(name for name, component_code in codes.items() if component_code == code)
            facts = sorted(
                (
                    fact
                    for fact in data.contexts
                    if fact.kind == kind and set(fact.evidence_ids) <= set(evidence_ids)
                ),
                key=lambda fact: canonical_json(fact.model_dump(mode="json")),
            )
            status = "unknown" if kind in missing else "known"
            if code == "T":
                start = min(item.timestamp for item in data.evidence if item.id in evidence_ids)
                valid = [
                    fact
                    for fact in facts
                    if _active_context(fact, start)
                    and any(
                        set(fact.evidence_ids).intersection(unit.evidence_ids) for unit in units
                    )
                ]
                families = {
                    unit.family
                    for fact in valid
                    for unit in units
                    if set(fact.evidence_ids).intersection(unit.evidence_ids)
                }
                count = min(len({fact.value for fact in valid}), len(families))
                points = min(6, 2 * max(0, count - 1))
                cited = sorted({identity for fact in valid for identity in fact.evidence_ids})
                details = {
                    "verified_tactics": sorted({fact.value for fact in valid}),
                    "verified_families": sorted(families),
                    "independent_tactic_count": count,
                }
            else:
                scored = [(_context_points(fact, data), fact) for fact in facts]
                points = max((value for value, _ in scored), default=0)
                cited = sorted(
                    {
                        identity
                        for value, fact in scored
                        if value == points and value > 0
                        for identity in fact.evidence_ids
                    }
                )
                details = {
                    "facts": [
                        {"points": value, **fact.model_dump(mode="json")} for value, fact in scored
                    ]
                }
            reason = (
                "Kontekst nie jest dostępny; zero punktów nie oznacza potwierdzenia bezpieczeństwa."
                if status == "unknown"
                else "Punkty wyłącznie z kwalifikującego się, wersjonowanego kontekstu "
                "powiązanego z dowodami; wartości nie sumują się."
                if points
                else "Dostępny kontekst nie spełnia warunków przyznania punktów."
            )
        components.append(
            RiskComponent(
                code=code,
                label=label,
                points=points,
                maximum=maximum,
                status=status,
                reason=reason,
                evidence_ids=cited,
                details=details,
            )
        )
    raw = sum(item.points for item in components)
    score = min(100, raw)
    return RiskResult(
        score=score,
        level=risk_level(score),
        raw_score=raw,
        clipping=score - raw,
        components=components,
        signal_units=units,
        missing_contexts=missing,
        confidence_status=confidence_status,
    )
