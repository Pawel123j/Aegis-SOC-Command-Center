"""Restart-safe final evaluation; incomplete windows never emit partial alerts."""

import hashlib
import hmac
from datetime import datetime, timedelta

from sqlalchemy import exists, select, text

from app.core.config import Settings
from app.infrastructure.database import ADMIN_LOCK_ID, Database, utcnow
from app.modules.correlation.admission import fenced_admission, missing_normalized, validated
from app.modules.correlation.builtin import BUILTIN_RULES
from app.modules.correlation.contracts import EVALUATOR_VERSION, MAX_CANDIDATES
from app.modules.correlation.engine import condition_matches, evaluate_anchor
from app.modules.correlation.models import CorrelationJob, CorrelationScope
from app.modules.correlation.persistence import persist_match
from app.modules.detections.models import RuleDeployment
from app.modules.detections.processing import RuleConfigurationError
from app.modules.ingestion.models import RawEvent
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.models import NormalizedEvent


def _process_one(database: Database, now: datetime) -> dict[str, int] | None:
    with database.sessions() as db:
        db.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": ADMIN_LOCK_ID})
        # A closed manifest is evaluated only after its whole normalized input
        # has been admitted, even when discovery needs several bounded batches.
        if db.scalar(select(exists(select(NormalizedEvent.event_id).where(missing_normalized())))):
            return None
        deployments = {
            row.id: row
            for row in db.scalars(
                select(RuleDeployment).where(
                    RuleDeployment.id.in_([rule.id for rule in BUILTIN_RULES])
                )
            )
        }
        if set(deployments) != {rule.id for rule in BUILTIN_RULES} or any(
            deployments[rule.id].rule_version != rule.version for rule in BUILTIN_RULES
        ):
            raise RuleConfigurationError("rule_configuration_mismatch")
        job = db.scalar(
            select(CorrelationJob)
            .join(CorrelationScope)
            .where(
                CorrelationJob.state == "pending",
                CorrelationJob.timestamp <= CorrelationScope.watermark,
            )
            .order_by(CorrelationJob.timestamp, CorrelationJob.event_id)
            .with_for_update(of=CorrelationJob, skip_locked=True)
            .limit(1)
        )
        if job is None:
            return None
        scope = db.get(CorrelationScope, job.namespace)
        assert scope is not None
        if scope.sealed_at is not None and not hmac.compare_digest(
            hashlib.sha256(canonical_json(scope.manifest)).hexdigest(), scope.manifest_sha256 or ""
        ):
            raise RuleConfigurationError("manifest_integrity_mismatch")
        if scope.sealed_at is not None:
            if not hmac.compare_digest(
                hashlib.sha256(canonical_json(scope.deployment_snapshot)).hexdigest(),
                scope.deployment_sha256 or "",
            ):
                raise RuleConfigurationError("deployment_snapshot_integrity_mismatch")
            if any(
                item["evaluator_version"] != EVALUATOR_VERSION for item in scope.deployment_snapshot
            ):
                raise RuleConfigurationError("rule_configuration_mismatch")
            deployments = {
                item["id"]: RuleDeployment(
                    id=item["id"],
                    rule_version=item["rule_version"],
                    version=item["version"],
                    enabled=item["enabled"],
                )
                for item in scope.deployment_snapshot
            }
            if set(deployments) != {rule.id for rule in BUILTIN_RULES} or any(
                deployments[rule.id].rule_version != rule.version for rule in BUILTIN_RULES
            ):
                raise RuleConfigurationError("rule_configuration_mismatch")
        snapshot = db.get(NormalizedEvent, job.event_id)
        raw = db.get(RawEvent, job.event_id)
        assert snapshot is not None and raw is not None
        try:
            anchor = validated(snapshot, raw)
        except (TypeError, ValueError):
            job.state, job.error_code, job.processed_at = "quarantined", "integrity_mismatch", now
            db.commit()
            return {"processed": 0, "quarantined": 1, "incomplete": 0, "alerts": 0}
        job.evaluated_rules = [
            {
                "id": rule.id,
                "version": rule.version,
                "enabled": deployments[rule.id].enabled,
                "deployment_version": deployments[rule.id].version,
                "evaluator_version": EVALUATOR_VERSION,
            }
            for rule in BUILTIN_RULES
        ]
        matches = []
        for rule in BUILTIN_RULES:
            deployment = deployments[rule.id]
            if not deployment.enabled or not condition_matches(
                rule.pattern.stages[-1].condition, snapshot.document
            ):
                continue
            if any(getattr(job, field) is None for field in rule.pattern.group_by):
                continue
            candidates = db.execute(
                select(NormalizedEvent, RawEvent)
                .join(CorrelationJob, CorrelationJob.event_id == NormalizedEvent.event_id)
                .join(RawEvent, RawEvent.id == NormalizedEvent.event_id)
                .where(
                    CorrelationJob.namespace == job.namespace,
                    CorrelationJob.state.in_(("pending", "processed", "incomplete")),
                    CorrelationJob.timestamp
                    >= anchor.timestamp - timedelta(seconds=rule.pattern.window_seconds),
                    CorrelationJob.timestamp <= anchor.timestamp,
                    *[
                        getattr(CorrelationJob, field) == getattr(job, field)
                        for field in rule.pattern.group_by
                    ],
                )
                .order_by(CorrelationJob.timestamp, CorrelationJob.event_id)
                .limit(MAX_CANDIDATES + 1)
            ).all()
            if len(candidates) > MAX_CANDIDATES:
                job.state, job.error_code, job.processed_at = "incomplete", "candidate_limit", now
                db.commit()
                return {"processed": 0, "quarantined": 0, "incomplete": 1, "alerts": 0}
            try:
                events = [validated(record, original) for record, original in candidates]
            except (TypeError, ValueError):
                job.state, job.error_code, job.processed_at = (
                    "incomplete",
                    "candidate_integrity_mismatch",
                    now,
                )
                db.commit()
                return {"processed": 0, "quarantined": 0, "incomplete": 1, "alerts": 0}
            match = evaluate_anchor(rule, anchor, events)
            if match is not None:
                matches.append(
                    (rule, deployment, match, {record.event_id: record for record, _ in candidates})
                )
        created = sum(
            persist_match(
                db, rule, deployment, anchor, match, snapshots, job.namespace, now, scope.watermark
            )
            for rule, deployment, match, snapshots in matches
        )
        job.state, job.processed_at, job.error_code = "processed", now, None
        job.evaluated_rules = [
            {
                "id": rule.id,
                "version": rule.version,
                "enabled": deployments[rule.id].enabled,
                "deployment_version": deployments[rule.id].version,
                "evaluator_version": EVALUATOR_VERSION,
            }
            for rule in BUILTIN_RULES
        ]
        db.commit()
        return {"processed": 1, "quarantined": 0, "incomplete": 0, "alerts": created}


def process_once(
    database: Database, settings: Settings, *, now: datetime | None = None
) -> dict[str, int]:
    observed = now or utcnow()
    counts = {
        **fenced_admission(database, settings.correlation_batch_size, observed),
        "processed": 0,
        "incomplete": 0,
        "alerts": 0,
    }
    for _ in range(settings.correlation_batch_size):
        result = _process_one(database, observed)
        if result is None:
            break
        for key, value in result.items():
            counts[key] += value
    return counts
