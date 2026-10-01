"""Pure event-time matching with strong entity keys and deterministic minimal proofs."""

import hashlib
from datetime import timedelta
from typing import Any

from app.modules.correlation.contracts import Condition, CorrelationRule
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.schemas import Account, NormalizedSecurityEvent, canonical_ip


def namespace(event: NormalizedSecurityEvent) -> str:
    return "live" if event.mode == "live" else f"replay:{event.dataset_id}:{event.run_id}"


def windows_identity(event: NormalizedSecurityEvent) -> bool:
    return (
        event.source.type in {"windows_auth", "windows_process"}
        or (event.host.os or "").casefold() == "windows"
    )


def principal_account(event: NormalizedSecurityEvent) -> Account:
    return (
        event.user.target
        if event.source.type == "windows_auth" and event.event.category == "authentication"
        else event.user
    )


def compatible_identity(
    event: NormalizedSecurityEvent, selected: list[NormalizedSecurityEvent]
) -> bool:
    if windows_identity(event):
        identity = principal_account(event).id
        known = {
            principal_account(other).id
            for other in selected
            if windows_identity(other)
            and principal_account(other).id not in {None, "-", "S-1-0-0", "0", "0x0"}
        }
        if len(known) > 1:
            return False
        if identity not in {None, "-", "S-1-0-0", "0", "0x0"} and known and identity not in known:
            return False
    if event.event.outcome == "failure":
        return True
    established = [other for other in selected if other.event.outcome != "failure"]
    for field in ("id", "provider", "host_id", "boot_id"):
        value = getattr(event.session, field)
        known = {
            getattr(other.session, field)
            for other in established
            if getattr(other.session, field) not in {None, "0", "0x0", "-"}
        }
        if value not in {None, "0", "0x0", "-"} and known and value not in known:
            return False
    return True


def entity_keys(event: NormalizedSecurityEvent) -> dict[str, str | None]:
    def key(parts: list[str]) -> str:
        return canonical_json(parts).decode()

    host = (
        key(["registered", event.host.id])
        if event.host.id
        else (
            key(["source", str(event.source_id), "host", event.host.name.casefold()])
            if event.host.name
            else None
        )
    )
    windows = windows_identity(event)
    account = principal_account(event)
    realm = account.realm.casefold() if account.realm and windows else account.realm
    name = account.name.casefold() if account.name and windows else account.name
    user: str | None
    if windows and realm and name and host:
        user = key(["windows_name", realm, name, host])
    elif account.id and host and account.id not in {"-", "S-1-0-0", "0", "0x0"}:
        user = key(["id", realm or "", account.id, host])
    else:
        user = key(["name", realm, name, host]) if realm and name and host else None
    return {
        "same_host": host,
        "same_user": user,
        "same_ip": canonical_ip(event.source.ip) if event.source.ip is not None else None,
        "same_process": key(["host", host, "entity", event.process.entity_id])
        if host and event.process.entity_id
        else None,
    }


def condition_matches(condition: Condition, document: dict[str, Any]) -> bool:
    if condition.all is not None:
        return bool(condition.all) and all(
            condition_matches(child, document) for child in condition.all
        )
    if condition.any is not None:
        return any(condition_matches(child, document) for child in condition.any)
    value: Any = document
    for part in (condition.field or "").split("."):
        value = value.get(part) if isinstance(value, dict) else None
    if not isinstance(value, str) or condition.value is None:
        return False
    # Windows/process names and normalized event terms are case-insensitive. Entity IDs are not.
    left, right = value.casefold(), condition.value.casefold()
    if condition.operator == "equals":
        return left == right
    if condition.operator == "contains":
        return right in left
    if condition.operator == "endswith":
        return left.endswith(right)
    return False


def evaluate_anchor(
    rule: CorrelationRule,
    anchor: NormalizedSecurityEvent,
    events: list[NormalizedSecurityEvent],
) -> dict[str, Any] | None:
    keys = entity_keys(anchor)
    if any(keys[field] is None for field in rule.pattern.group_by):
        return None
    if not condition_matches(rule.pattern.stages[-1].condition, anchor.model_dump(mode="json")):
        return None
    start = anchor.timestamp - timedelta(seconds=rule.pattern.window_seconds)
    candidates = sorted(
        (
            event
            for event in events
            if namespace(event) == namespace(anchor)
            and start <= event.timestamp <= anchor.timestamp
            and all(entity_keys(event)[field] == keys[field] for field in rule.pattern.group_by)
        ),
        key=lambda event: (event.timestamp, event.event_id),
    )
    selected: list[list[NormalizedSecurityEvent]] = []
    boundary = None
    for stage in reversed(rule.pattern.stages):
        later = [event for selected_stage in selected for event in selected_stage] or [anchor]
        eligible = [
            event
            for event in candidates
            if (boundary is None or event.timestamp < boundary)
            and condition_matches(stage.condition, event.model_dump(mode="json"))
            and compatible_identity(event, later)
            and (
                rule.id != "possible_multi_stage_compromise"
                or stage.name != "powershell_started"
                or (
                    entity_keys(event)["same_process"] is not None
                    and entity_keys(event)["same_process"] == entity_keys(anchor)["same_process"]
                )
            )
        ]
        if len(eligible) < stage.count:
            return None
        chosen = eligible[-stage.count :]
        if boundary is None and anchor.event_id not in {event.event_id for event in chosen}:
            # Simultaneous events are sorted for counters, never treated as ordered stages.
            chosen = (
                [event for event in eligible if event.event_id != anchor.event_id][
                    -(stage.count - 1) :
                ]
                if stage.count > 1
                else []
            )
            chosen = sorted([*chosen, anchor], key=lambda event: (event.timestamp, event.event_id))
        selected.insert(0, chosen)
        boundary = chosen[0].timestamp
    contributors = [event for stage in selected for event in stage]
    if any(
        not compatible_identity(
            event, [other for other in contributors if other.event_id != event.event_id]
        )
        for event in contributors
    ):
        return None
    established = [event for event in contributors if event.event.outcome != "failure"]
    for field in ("id", "provider", "host_id", "boot_id"):
        known = {
            getattr(event.session, field)
            for event in established
            if getattr(event.session, field) not in {None, "0", "0x0", "-"}
        }
        if len(known) > 1:
            return None
    if rule.id == "possible_multi_stage_compromise":
        process_events = (selected[2][0], selected[4][0])
        process_keys = [entity_keys(event)["same_process"] for event in process_events]
        if process_keys[0] is None or process_keys[0] != process_keys[1]:
            return None
    return {
        "event_ids": [str(event.event_id) for event in contributors],
        "event_timestamp": anchor.timestamp.isoformat(),
        "reason": {
            "kind": rule.pattern.kind,
            "window_seconds": rule.pattern.window_seconds,
            "first_seen": contributors[0].timestamp.isoformat(),
            "last_seen": anchor.timestamp.isoformat(),
            "group_by": {field: keys[field] for field in rule.pattern.group_by},
            "stages": [
                {
                    "name": stage.name,
                    "required_count": stage.count,
                    "event_ids": [str(event.event_id) for event in chosen],
                }
                for stage, chosen in zip(rule.pattern.stages, selected, strict=True)
            ],
            "assessment": "potential_activity_requires_analyst_review",
        },
    }


def detection_key(rule: CorrelationRule, match: dict[str, Any], scope: str) -> str:
    from app.modules.correlation.contracts import EVALUATOR_VERSION

    return hashlib.sha256(
        canonical_json(
            {
                "namespace": scope,
                "rule_id": rule.id,
                "rule_version": rule.version,
                "evaluator_version": EVALUATOR_VERSION,
                "event_ids": match["event_ids"],
            }
        )
    ).hexdigest()
