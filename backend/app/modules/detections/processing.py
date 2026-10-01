"""Atomic per-event evaluation, independent of ClickHouse and wall-clock windows."""

import hashlib
import hmac
from copy import deepcopy
from typing import Any
from uuid import uuid4

from sqlalchemy import exists, select, text
from sqlalchemy.dialects.postgresql import insert

from app.core.config import Settings
from app.infrastructure.database import ADMIN_LOCK_ID, Database, utcnow
from app.modules.alerts.models import Alert
from app.modules.audit.service import append_audit
from app.modules.detections.builtin import BUILTIN_RULES, EVALUATOR_VERSION, Match, evaluate
from app.modules.detections.models import DetectionJob, RuleDeployment
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.models import NormalizedEvent
from app.modules.normalization.schemas import NormalizedSecurityEvent


class RuleConfigurationError(RuntimeError):
    """A deployment/catalog mismatch leaves the checkpoint pending for repair."""


def enqueue_normalized(database: Database, limit: int) -> int:
    with database.sessions() as session:
        candidates = (
            select(NormalizedEvent.event_id)
            .where(
                ~exists(
                    select(DetectionJob.event_id).where(
                        DetectionJob.event_id == NormalizedEvent.event_id
                    )
                )
            )
            .order_by(NormalizedEvent.processed_at, NormalizedEvent.event_id)
            .limit(limit)
        )
        rows = session.execute(
            insert(DetectionJob)
            .from_select(["event_id"], candidates, include_defaults=False)
            .on_conflict_do_nothing(index_elements=[DetectionJob.event_id])
            .returning(DetectionJob.event_id)
        ).all()
        session.commit()
        return len(rows)


def _key(event: NormalizedSecurityEvent, match: Match) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "event_id": str(event.event_id),
                "dataset_id": str(event.dataset_id),
                "mode": event.mode,
                "run_id": str(event.run_id),
                "rule_id": match.rule.id,
                "rule_version": match.rule.version,
                "evaluator_version": EVALUATOR_VERSION,
            }
        )
    ).hexdigest()


def _process_one(database: Database) -> dict[str, int] | None:
    with database.sessions() as session:
        # Use the same lock order as deployment changes and authority revocation.
        # Evaluation is pure and bounded; no network I/O occurs in this transaction.
        session.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": ADMIN_LOCK_ID})
        deployments = {row.id: row for row in session.scalars(select(RuleDeployment))}
        if set(deployments) != {rule.id for rule in BUILTIN_RULES} or any(
            deployments[rule.id].rule_version != rule.version for rule in BUILTIN_RULES
        ):
            raise RuleConfigurationError("rule_configuration_mismatch")
        job = session.scalar(
            select(DetectionJob)
            .where(DetectionJob.state == "pending")
            .order_by(DetectionJob.created_at, DetectionJob.event_id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if job is None:
            return None
        snapshot = session.get(NormalizedEvent, job.event_id)
        now = utcnow()
        try:
            if snapshot is None or not hmac.compare_digest(
                hashlib.sha256(canonical_json(snapshot.document)).hexdigest(),
                snapshot.document_sha256,
            ):
                raise ValueError("integrity_mismatch")
            event = NormalizedSecurityEvent.model_validate(snapshot.document)
            if event.event_id != job.event_id or event.timestamp != snapshot.timestamp:
                raise ValueError("integrity_mismatch")
        except (TypeError, ValueError):
            job.state = "quarantined"
            job.error_code = "integrity_mismatch"
            job.processed_at = now
            session.commit()
            return {"processed": 0, "quarantined": 1, "alerts": 0}
        active = {rule.id for rule in BUILTIN_RULES if deployments[rule.id].enabled}
        try:
            matches = [match for match in evaluate(snapshot.document) if match.rule.id in active]
        except Exception:
            job.state = "quarantined"
            job.error_code = "evaluation_failed"
            job.processed_at = now
            session.commit()
            return {"processed": 0, "quarantined": 1, "alerts": 0}
        created = 0
        for match in matches:
            values: dict[str, Any] = {
                "id": uuid4(),
                "detection_key": _key(event, match),
                "event_id": event.event_id,
                "source_id": event.source_id,
                "dataset_id": event.dataset_id,
                "run_id": event.run_id,
                "mode": event.mode,
                "rule_id": match.rule.id,
                "rule_version": match.rule.version,
                "evaluator_version": EVALUATOR_VERSION,
                "severity": match.rule.severity,
                "title": match.rule.title,
                "status": "new",
                "event_timestamp": event.timestamp,
                "created_at": now,
                "updated_at": now,
                "version": 1,
                "rule_snapshot": match.rule.snapshot(),
                "event_snapshot": deepcopy(snapshot.document),
                "reason": deepcopy(match.reason),
                "event_sha256": snapshot.document_sha256,
                "risk_score": None,
            }
            alert_id = session.scalar(
                insert(Alert)
                .values(**values)
                .on_conflict_do_nothing(index_elements=[Alert.detection_key])
                .returning(Alert.id)
            )
            if alert_id is not None:
                append_audit(
                    session,
                    action="alert.created",
                    outcome="success",
                    request_id=str(uuid4()),
                    object_type="alert",
                    object_id=str(alert_id),
                    details={
                        "event_id": str(event.event_id),
                        "rule_id": match.rule.id,
                        "rule_version": match.rule.version,
                        "evaluator_version": EVALUATOR_VERSION,
                    },
                )
                created += 1
        job.state = "processed"
        job.processed_at = now
        job.error_code = None
        job.evaluated_rules = [
            {
                "id": rule.id,
                "version": rule.version,
                "deployment_version": deployments[rule.id].version,
                "evaluator_version": EVALUATOR_VERSION,
            }
            for rule in BUILTIN_RULES
            if rule.id in active
        ]
        session.commit()
        return {"processed": 1, "quarantined": 0, "alerts": created}


def process_once(database: Database, settings: Settings) -> dict[str, int]:
    enqueue_normalized(database, settings.pipeline_batch_size)
    counts = {"processed": 0, "quarantined": 0, "alerts": 0}
    for _ in range(settings.pipeline_batch_size):
        result = _process_one(database)
        if result is None:
            break
        for key, value in result.items():
            counts[key] += value
    return counts
