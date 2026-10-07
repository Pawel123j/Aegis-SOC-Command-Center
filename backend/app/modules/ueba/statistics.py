"""Deterministic statistics over unique, source-verified, complete UTC days.

Scores are fixed triage weights, not probabilities or changes to alert risk.
Absent facts are never replaced with assumed users, hosts, IPs or privileges.
"""

import math
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from app.modules.entities.identity import EntityDescriptor
from app.modules.normalization.schemas import NormalizedSecurityEvent, canonical_ip
from app.modules.ueba.schemas import (
    Baseline,
    Evidence,
    Indicator,
    Observation,
    UebaEntity,
    UebaReport,
    UebaScope,
)

EXCLUDED_QUALITY = {"timestamp_from_received_at", "missing_source_timestamp", "inferred_year"}
ADMIN_TOOLS = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wmic.exe",
        "psexec.exe",
        "sc.exe",
        "schtasks.exe",
        "reg.exe",
        "net.exe",
        "net1.exe",
        "sudo",
        "su",
        "systemctl",
    }
)


@dataclass(frozen=True)
class VerifiedEvent:
    event: NormalizedSecurityEvent
    document_sha256: str
    descriptors: tuple[EntityDescriptor, ...]

    def roles(self, entity_id: UUID) -> set[str]:
        return {item.role for item in self.descriptors if item.entity_id == entity_id}


def _active(events: list[VerifiedEvent]) -> int:
    return len({item.event.timestamp.date() for item in events})


def _evidence(events: list[VerifiedEvent]) -> list[Evidence]:
    return [
        Evidence(
            event_id=item.event.event_id,
            timestamp=item.event.timestamp,
            document_sha256=item.document_sha256,
        )
        for item in events[:25]
    ]


def _login(item: VerifiedEvent, entity: UebaEntity, outcome: str) -> bool:
    event = item.event
    if (
        event.event.category != "authentication"
        or event.event.type != "start"
        or event.event.outcome != outcome
    ):
        return False
    if entity.kind == "host":
        return True
    # Windows Subject and a caller of su are not the authenticated target account.
    # Missing target evidence must never turn the actor into the login target.
    if event.source.type == "windows_auth" or event.event.action in {"windows_logon", "su_session"}:
        return "target" in item.roles(entity.id)
    target = any(d.entity_type == "user" and d.role == "target" for d in item.descriptors)
    return ("target" if target else "actor") in item.roles(entity.id)


def _process(item: VerifiedEvent, entity: UebaEntity) -> bool:
    return (
        item.event.event.category == "process"
        and item.event.event.type == "start"
        and item.event.event.outcome != "failure"
        and bool(item.event.process.executable or item.event.process.name)
        and (entity.kind == "host" or "actor" in item.roles(entity.id))
    )


def _tool(item: VerifiedEvent) -> str | None:
    event = item.event
    value = event.process.executable or event.process.name
    if value is None:
        return None
    # Windows separators and case apply only to Windows observations. In POSIX,
    # backslashes and uppercase are genuine filename characters, not aliases.
    windows = (
        event.source.type in {"windows_auth", "windows_process"}
        or (event.host.os or "").casefold() == "windows"
    )
    name = (
        value.replace("\\", "/").rsplit("/", 1)[-1].casefold()
        if windows
        else (value.rsplit("/", 1)[-1])
    )
    return name if name in ADMIN_TOOLS else None


def _host(item: VerifiedEvent) -> str | None:
    return next((str(d.entity_id) for d in item.descriptors if d.entity_type == "host"), None)


def _ip(item: VerifiedEvent) -> str | None:
    return canonical_ip(item.event.source.ip) if item.event.source.ip is not None else None


def _novelty(
    identifier: Literal["unusual_login_hour", "new_login_ip", "new_login_host", "first_admin_tool"],
    baseline: list[VerifiedEvent],
    observed: list[VerifiedEvent],
    value: Callable[[VerifiedEvent], str | None],
    score: int,
    ready: bool,
    *,
    tool: bool = False,
) -> Indicator:
    if not tool:
        baseline = [item for item in baseline if value(item) is not None]
        observed = [item for item in observed if value(item) is not None]
    known = sorted({v for item in baseline if (v := value(item)) is not None})
    observed_values = sorted({v for item in observed if (v := value(item)) is not None})
    unfamiliar = [item for item in observed if (v := value(item)) is not None and v not in known]
    sufficient = ready and len(baseline) >= 10 and _active(baseline) >= 3
    # A process baseline can validly contain no administrative tools. For IP/host
    # novelty, absent baseline facts cannot establish that a new value is unusual.
    if not tool and not known:
        sufficient = False
    status: Literal["anomaly", "normal", "insufficient_data"] = (
        "insufficient_data" if not sufficient else "anomaly" if unfamiliar else "normal"
    )
    label = {
        "unusual_login_hour": "godziny udanych logowań w UTC",
        "new_login_ip": "źródłowe adresy IP udanych logowań",
        "new_login_host": "hosty rejestrujące udane logowania",
        "first_admin_tool": "nazwy zaobserwowanych narzędzi administracyjnych",
    }[identifier]
    explanation = (
        f"Porównano {label} z poprzednimi 28 pełnymi dniami UTC. "
        f"Baza porównawcza: {len(baseline)} zdarzeń danego rodzaju z {_active(baseline)} dni; "
        f"obserwacja: {len(observed)} zdarzeń, w tym {len(unfamiliar)} z nową wartością. "
        + (
            "Wymagana jest kompletna baza profilu oraz co najmniej 10 zdarzeń tego rodzaju z 3 dni"
            + (" z zaobserwowaną wartością porównawczą." if not tool else ".")
            if not sufficient
            else "Nowa wartość nie dowodzi ataku ani podwyższonych uprawnień."
        )
    )
    return Indicator(
        id=identifier,
        status=status,
        score=score if status == "anomaly" else 0,
        explanation=explanation,
        baseline_event_count=len(baseline),
        baseline_active_days=_active(baseline),
        baseline_values=known,
        observed_count=len(observed),
        observed_values=observed_values,
        evidence_total=len(unfamiliar) if status == "anomaly" else 0,
        evidence=_evidence(unfamiliar) if status == "anomaly" else [],
    )


def _burst(
    identifier: Literal["failed_login_burst", "activity_burst"],
    baseline: list[VerifiedEvent],
    observed: list[VerifiedEvent],
    start: datetime,
    floor: int,
    score: int,
    ready: bool,
) -> Indicator:
    days = Counter((item.event.timestamp.date() - start.date()).days for item in baseline)
    bins = [days[index] for index in range(28)]
    mean = sum(bins) / 28
    deviation = math.sqrt(sum((count - mean) ** 2 for count in bins) / 28)
    threshold = max(floor, math.ceil(mean + 3 * deviation), math.ceil(3 * mean))
    anomaly = ready and len(observed) >= threshold
    return Indicator(
        id=identifier,
        status="anomaly" if anomaly else "normal" if ready else "insufficient_data",
        score=score if anomaly else 0,
        baseline_event_count=len(baseline),
        baseline_active_days=_active(baseline),
        observed_count=len(observed),
        daily_mean=mean,
        daily_stddev=deviation,
        threshold=threshold,
        explanation=(
            f"Uwzględniono 28 dni UTC, także dni bez zdarzeń. Próg = max({floor}, "
            f"zaokrąglone w górę (średnia + 3 × odchylenie standardowe populacji), "
            f"zaokrąglone w górę (3 × średnia)) = {threshold}. "
            f"Zaobserwowano {len(observed)} zdarzeń; osiągnięcie progu oznacza anomalię. "
            + (
                "Baza porównawcza profilu jest niekompletna; nie stwierdzono anomalii."
                if not ready
                else "Wynik statystyczny nie dowodzi złośliwego działania."
            )
        ),
        evidence_total=len(observed) if anomaly else 0,
        evidence=_evidence(observed) if anomaly else [],
    )


def report(
    entity: UebaEntity,
    scope: UebaScope,
    events: list[VerifiedEvent],
    start: datetime,
    observed_start: datetime,
    end: datetime,
    pending: int,
    *,
    cross_host: bool,
    as_of: datetime,
) -> UebaReport:
    # Defensive deduplication also makes the pure evaluator safe for repeated roles.
    unique = {item.event.event_id: item for item in events}
    ordered = sorted(unique.values(), key=lambda item: (item.event.timestamp, item.event.event_id))
    baseline_all = [item for item in ordered if start <= item.event.timestamp < observed_start]
    observed_all = [item for item in ordered if observed_start <= item.event.timestamp < end]
    baseline = [
        item for item in baseline_all if not EXCLUDED_QUALITY.intersection(item.event.quality)
    ]
    observed = [
        item for item in observed_all if not EXCLUDED_QUALITY.intersection(item.event.quality)
    ]
    status: Literal["ready", "cold_start", "index_pending", "unsupported"] = (
        "unsupported"
        if entity.kind not in {"host", "user"}
        else "index_pending"
        if pending
        else "cold_start"
        if len(baseline) < 20 or _active(baseline) < 7
        else "ready"
    )
    ready = status == "ready"
    indicators: list[Indicator] = []
    if status != "unsupported":
        successful = [item for item in baseline if _login(item, entity, "success")]
        new_successful = [item for item in observed if _login(item, entity, "success")]
        indicators.append(
            _novelty(
                "unusual_login_hour",
                successful,
                new_successful,
                lambda item: f"{item.event.timestamp.hour:02d}:00 UTC",
                35,
                ready,
            )
        )
        indicators.append(_novelty("new_login_ip", successful, new_successful, _ip, 40, ready))
        if entity.kind == "user" and cross_host:
            indicators.append(
                _novelty("new_login_host", successful, new_successful, _host, 45, ready)
            )
        else:
            indicators.append(
                Indicator(
                    id="new_login_host",
                    status="unsupported",
                    score=0,
                    explanation=(
                        "Porównanie między hostami wymaga pełnego SID konta w jednym źródle. "
                        "Tożsamości ograniczone do hosta lub zdarzenia nie są łączone."
                    ),
                )
            )
        processes = [item for item in baseline if _process(item, entity)]
        new_processes = [item for item in observed if _process(item, entity)]
        indicators.append(
            _novelty("first_admin_tool", processes, new_processes, _tool, 50, ready, tool=True)
        )
        indicators.append(
            _burst(
                "failed_login_burst",
                [item for item in baseline if _login(item, entity, "failure")],
                [item for item in observed if _login(item, entity, "failure")],
                start,
                5,
                55,
                ready,
            )
        )
        indicators.append(_burst("activity_burst", baseline, observed, start, 20, 30, ready))
        indicators.append(
            Indicator(
                id="admin_account_use",
                status="unsupported",
                score=0,
                explanation=(
                    "Dane znormalizowane nie zawierają potwierdzonej informacji o uprawnieniach "
                    "ani członkostwie w grupie administratorów. Nazwy kont i narzędzi "
                    "nie potwierdzają uprawnień konta."
                ),
            )
        )
    return UebaReport(
        as_of=as_of,
        entity=entity,
        scope=scope,
        status=status,
        pending_events=pending,
        score=max((item.score for item in indicators), default=0) if ready else None,
        baseline=Baseline(
            from_=start,
            to=observed_start,
            event_count=len(baseline_all),
            eligible_events=len(baseline),
            excluded_timestamp_events=len(baseline_all) - len(baseline),
            active_days=_active(baseline),
        ),
        observation=Observation(
            from_=observed_start,
            to=end,
            event_count=len(observed_all),
            eligible_events=len(observed),
            excluded_timestamp_events=len(observed_all) - len(observed),
        ),
        indicators=indicators,
    )
