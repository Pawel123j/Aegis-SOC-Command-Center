"""Derive every target from verified alert evidence, never from arbitrary operator text."""

from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.modules.alerts.evidence import verified_events
from app.modules.alerts.models import Alert
from app.modules.ingestion.schemas import canonical_json
from app.modules.intelligence.matching import frozen_event
from app.modules.normalization.schemas import NormalizedSecurityEvent, canonical_ip
from app.modules.risk.service import current
from app.modules.soar.schemas import RunInput, digest


def event_targets(alert: Alert) -> list[NormalizedSecurityEvent]:
    try:
        return verified_events(alert)
    except (ValueError, TypeError, KeyError):
        raise ApiError(409, "evidence_integrity_mismatch", "Alert evidence is invalid") from None


def target_view(event: NormalizedSecurityEvent) -> dict[str, Any]:
    return {
        "event_id": str(event.event_id),
        "timestamp": event.timestamp.isoformat(),
        "source_ip": canonical_ip(event.source.ip) if event.source.ip else None,
        "destination_ip": canonical_ip(event.destination.ip) if event.destination.ip else None,
        "host": event.host.name or event.host.id,
    }


def capture_context(db: Session, alert: Alert, data: RunInput) -> dict[str, Any]:
    event = next(
        (e for e in event_targets(alert) if e.event_id == (data.event_id or alert.event_id)), None
    )
    if event is None:
        raise ApiError(422, "soar_target_mismatch", "Event must belong to the selected alert")
    target = target_view(event)
    risk = current(db, alert)
    ti = frozen_event(db, event.event_id)
    # A stored TI receipt can contain many indicators. Keep exactly the selected
    # IP's existing proof, without querying today's catalog or inventing reputation.
    ip = target[f"{data.ip_field}_ip"]
    ti["matches"] = [
        item
        for item in ti["matches"]
        if item["revision_snapshot"]["type"] == "ip" and item["revision_snapshot"]["value"] == ip
    ]
    ti["match_count"] = len(ti["matches"])
    result = {
        **target,
        "ip": ip,
        "ip_field": data.ip_field,
        "event_sha256": digest(event.model_dump(mode="json")),
        "alert_id": str(alert.id),
        "alert_title": alert.title,
        "source_id": str(event.source_id),
        "mode": alert.mode,
        "dataset_id": str(alert.dataset_id),
        "data_run_id": str(alert.run_id),
        "intelligence": ti,
        "risk": None
        if risk is None
        else {
            "calculation_id": str(risk.id),
            "score": risk.score,
            "level": risk.level,
            "policy_version": risk.policy_version,
            "policy_hash": risk.policy_hash,
            "input_sha256": risk.input_sha256,
            "components": [part.model_dump(mode="json") for part in risk.components],
        },
    }
    # Leave space for JSONB whitespace and action envelopes; fail, never truncate.
    if len(canonical_json(result)) > 24000:
        raise ApiError(409, "soar_context_limit", "Selected proof exceeds the workflow limit")
    return result


def verify_context(alert: Alert, context: dict[str, Any]) -> None:
    event = next((e for e in event_targets(alert) if str(e.event_id) == context["event_id"]), None)
    if (
        event is None
        or digest(event.model_dump(mode="json")) != context["event_sha256"]
        or str(alert.id) != context["alert_id"]
        or alert.mode != context["mode"]
        or str(alert.dataset_id) != context["dataset_id"]
        or str(alert.run_id) != context["data_run_id"]
    ):
        raise ApiError(409, "soar_context_integrity", "Workflow evidence is invalid")
    if target_view(event) != {key: context[key] for key in target_view(event)}:
        raise ApiError(409, "soar_context_integrity", "Workflow target is invalid")
    if context["ip"] != context[f"{context['ip_field']}_ip"]:
        raise ApiError(409, "soar_context_integrity", "Workflow IP is invalid")


def alert_record(db: Session, identifier: UUID) -> Alert:
    alert = db.get(Alert, identifier)
    if alert is None:
        raise ApiError(404, "alert_not_found", "Alert not found")
    return alert
