"""Explicit closed input manifests keep archived replay separate from live time."""

import hashlib
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.infrastructure.database import utcnow
from app.modules.audit.service import append_audit
from app.modules.correlation.admission import ensure_scope
from app.modules.correlation.builtin import BUILTIN_RULES
from app.modules.correlation.contracts import EVALUATOR_VERSION, ReplayFinalize
from app.modules.correlation.models import CorrelationScope
from app.modules.detections.models import RuleDeployment
from app.modules.ingestion.models import IngestCapacity, RawEvent
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.models import NormalizedEvent


def seal_view(scope: CorrelationScope) -> dict[str, Any]:
    return {
        "namespace": scope.namespace,
        "watermark": scope.watermark,
        "sealed_at": scope.sealed_at,
        "manifest_sha256": scope.manifest_sha256,
        "event_count": len(scope.manifest),
    }


def finalize_replay(
    db: Session, data: ReplayFinalize, *, actor_id: Any, request_id: str
) -> CorrelationScope:
    if data.run_id.int == 0:
        raise ApiError(422, "invalid_replay_scope", "Replay requires a nonzero run ID")
    db.scalar(select(IngestCapacity).where(IngestCapacity.id == 1).with_for_update())
    scope = ensure_scope(db, f"replay:{data.dataset_id}:{data.run_id}")
    if scope.sealed_at is not None:
        if len(scope.manifest) != data.expected_event_count:
            raise ApiError(409, "replay_already_finalized", "Replay manifest is already finalized")
        return scope
    filters = (
        RawEvent.mode == "replay",
        RawEvent.dataset_id == data.dataset_id,
        RawEvent.run_id == data.run_id,
    )
    count = int(db.scalar(select(func.count()).select_from(RawEvent).where(*filters)) or 0)
    if count != data.expected_event_count:
        raise ApiError(
            409,
            "replay_count_mismatch",
            "The expected input count does not match the accepted replay",
        )
    records = db.execute(
        select(
            RawEvent.id,
            RawEvent.received_at,
            NormalizedEvent.timestamp,
            NormalizedEvent.document_sha256,
        )
        .join(NormalizedEvent, NormalizedEvent.event_id == RawEvent.id)
        .where(*filters)
        .order_by(RawEvent.id)
    ).all()
    if len(records) != count:
        raise ApiError(
            409, "replay_not_normalized", "All replay inputs must be normalized before finalization"
        )
    manifest = [
        {"event_id": str(event_id), "document_sha256": digest} for event_id, _, _, digest in records
    ]
    scope.manifest = manifest
    scope.manifest_sha256 = hashlib.sha256(canonical_json(manifest)).hexdigest()
    scope.sealed_at = utcnow()
    scope.watermark = max(timestamp for _, _, timestamp, _ in records)
    deployments = {
        row.id: row
        for row in db.scalars(
            select(RuleDeployment).where(RuleDeployment.id.in_([rule.id for rule in BUILTIN_RULES]))
        )
    }
    if set(deployments) != {rule.id for rule in BUILTIN_RULES} or any(
        deployments[rule.id].rule_version != rule.version for rule in BUILTIN_RULES
    ):
        raise ApiError(503, "rules_unavailable", "Rule deployment version is unavailable")
    scope.deployment_snapshot = [
        {
            "id": rule.id,
            "rule_version": rule.version,
            "version": deployments[rule.id].version,
            "enabled": deployments[rule.id].enabled,
            "evaluator_version": EVALUATOR_VERSION,
        }
        for rule in BUILTIN_RULES
    ]
    scope.deployment_sha256 = hashlib.sha256(canonical_json(scope.deployment_snapshot)).hexdigest()
    append_audit(
        db,
        action="correlation.replay_finalized",
        outcome="success",
        request_id=request_id,
        actor_id=actor_id,
        object_type="correlation_scope",
        object_id=scope.namespace,
        details={
            "event_count": count,
            "manifest_sha256": scope.manifest_sha256,
            "deployment_sha256": scope.deployment_sha256,
        },
    )
    return scope
