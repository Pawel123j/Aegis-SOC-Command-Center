"""Read and verify original immutable contributor snapshots, including legacy alerts."""

import hashlib
import hmac
from typing import Any

from app.modules.alerts.models import Alert
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.schemas import NormalizedSecurityEvent


def contributors(alert: Alert) -> list[dict[str, Any]]:
    return alert.event_snapshots or [
        {
            "event_id": str(alert.event_id),
            "event_sha256": alert.event_sha256,
            "event_snapshot": alert.event_snapshot,
        }
    ]


def verified_events(alert: Alert) -> list[NormalizedSecurityEvent]:
    if alert.evaluator_version.startswith("correlation-") and not alert.event_snapshots:
        raise ValueError("evidence_integrity_mismatch")
    result = []
    identities = set()
    for item in contributors(alert):
        document = item["event_snapshot"]
        if not hmac.compare_digest(
            hashlib.sha256(canonical_json(document)).hexdigest(), item["event_sha256"]
        ):
            raise ValueError("evidence_integrity_mismatch")
        event = NormalizedSecurityEvent.model_validate(document)
        if str(event.event_id) != item["event_id"]:
            raise ValueError("evidence_integrity_mismatch")
        if event.event_id in identities:
            raise ValueError("evidence_integrity_mismatch")
        identities.add(event.event_id)
        if (
            event.mode != alert.mode
            or event.run_id != alert.run_id
            or (alert.mode == "replay" and event.dataset_id != alert.dataset_id)
        ):
            raise ValueError("evidence_integrity_mismatch")
        result.append(event)
    anchor = next((event for event in result if event.event_id == alert.event_id), None)
    if (
        anchor is None
        or anchor.model_dump(mode="json") != alert.event_snapshot
        or hashlib.sha256(canonical_json(alert.event_snapshot)).hexdigest() != alert.event_sha256
    ):
        raise ValueError("evidence_integrity_mismatch")
    if (
        anchor.source_id != alert.source_id
        or anchor.dataset_id != alert.dataset_id
        or anchor.timestamp != alert.event_timestamp
    ):
        raise ValueError("evidence_integrity_mismatch")
    if alert.evaluator_version.startswith("correlation-"):
        stages = alert.rule_snapshot["pattern"]["stages"]
        expected_ids = [
            identity for stage in alert.reason["stages"] for identity in stage["event_ids"]
        ]
        if len(result) != sum(stage["count"] for stage in stages) or expected_ids != [
            str(event.event_id) for event in result
        ]:
            raise ValueError("evidence_integrity_mismatch")
    return result
