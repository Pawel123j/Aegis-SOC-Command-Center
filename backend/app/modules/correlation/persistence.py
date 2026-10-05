"""Alert, all immutable contributors, audit and automatic case share one transaction."""

from copy import deepcopy
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.modules.alerts.models import Alert
from app.modules.audit.service import append_audit
from app.modules.correlation.contracts import EVALUATOR_VERSION, CorrelationRule
from app.modules.correlation.engine import detection_key
from app.modules.detections.models import RuleDeployment
from app.modules.entities.indexing import index_alert
from app.modules.incidents.service import automatic_incident
from app.modules.mitre.service import record_mapping
from app.modules.normalization.models import NormalizedEvent
from app.modules.normalization.schemas import NormalizedSecurityEvent
from app.modules.risk.service import score_subject


def persist_match(
    db: Session,
    rule: CorrelationRule,
    deployment: RuleDeployment,
    anchor: NormalizedSecurityEvent,
    match: dict[str, Any],
    snapshots: dict[UUID, NormalizedEvent],
    scope: str,
    now: datetime,
    watermark: datetime | None,
) -> bool:
    snapshot = snapshots[anchor.event_id]
    proof = [
        {
            "event_id": event_id,
            "event_sha256": snapshots[UUID(event_id)].document_sha256,
            "event_snapshot": deepcopy(snapshots[UUID(event_id)].document),
        }
        for event_id in match["event_ids"]
    ]
    request_id = str(uuid4())
    alert_id = db.scalar(
        insert(Alert)
        .values(
            id=uuid4(),
            detection_key=detection_key(rule, match, scope),
            event_id=anchor.event_id,
            source_id=anchor.source_id,
            dataset_id=anchor.dataset_id,
            run_id=anchor.run_id,
            mode=anchor.mode,
            rule_id=rule.id,
            rule_version=rule.version,
            evaluator_version=EVALUATOR_VERSION,
            severity=rule.severity,
            title=rule.title,
            status="new",
            event_timestamp=anchor.timestamp,
            created_at=now,
            updated_at=now,
            version=1,
            rule_snapshot={**rule.snapshot(), "deployment_version": deployment.version},
            event_snapshot=deepcopy(snapshot.document),
            event_snapshots=proof,
            event_sha256=snapshot.document_sha256,
            risk_score=None,
            reason={
                **deepcopy(match["reason"]),
                "deployment_version": deployment.version,
                "finalized_watermark": watermark.isoformat() if watermark else None,
            },
        )
        .on_conflict_do_nothing(index_elements=[Alert.detection_key])
        .returning(Alert.id)
    )
    if alert_id is None:
        return False
    append_audit(
        db,
        action="alert.created",
        outcome="success",
        request_id=request_id,
        object_type="alert",
        object_id=str(alert_id),
        details={
            "event_id": str(anchor.event_id),
            "event_count": len(proof),
            "rule_id": rule.id,
            "rule_version": rule.version,
            "evaluator_version": EVALUATOR_VERSION,
            "deployment_version": deployment.version,
        },
    )
    alert = db.get(Alert, alert_id)
    assert alert is not None
    index_alert(db, alert)
    score_subject(db, alert, request_id=request_id, trigger="alert_created")
    record_mapping(db, alert)
    automatic_incident(db, alert, request_id=request_id)
    return True
