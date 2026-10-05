"""Transactional immutable calculations; reads never create or refresh scores."""

import hashlib
from typing import Any, Literal, cast
from uuid import UUID, uuid4

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value

from app.modules.alerts.models import Alert
from app.modules.audit.service import append_audit
from app.modules.incidents.models import Incident, IncidentAlert
from app.modules.ingestion.schemas import canonical_json
from app.modules.risk import engine_v4
from app.modules.risk.engine import POLICY_HASH, POLICY_VERSION, calculate
from app.modules.risk.inputs import build_input
from app.modules.risk.models import RiskCalculation
from app.modules.risk.schemas import RiskCalculationView, RiskHistory


def calculation_view(row: RiskCalculation) -> RiskCalculationView:
    return RiskCalculationView(
        **row.explanation,
        id=row.id,
        subject_type=cast(Literal["alert", "incident"], row.subject_type),
        subject_id=row.subject_id,
        subject_revision=row.subject_revision,
        created_at=row.created_at,
        actor_id=row.actor_id,
        trigger=row.trigger,
        previous_id=row.previous_id,
        policy_version=row.policy_version,
        policy_hash=row.policy_hash,
        input_sha256=row.input_sha256,
        input_snapshot=row.input_snapshot,
        excluded_alert_ids=row.input_snapshot["excluded_alert_ids"],
    )


def current(db: Session, subject: Alert | Incident) -> RiskCalculationView | None:
    row = (
        db.get(RiskCalculation, subject.risk_calculation_id)
        if subject.risk_calculation_id
        else None
    )
    return calculation_view(row) if row else None


def history(db: Session, subject: Alert | Incident, limit: int) -> RiskHistory:
    kind = "alert" if isinstance(subject, Alert) else "incident"
    rows = list(
        db.scalars(
            select(RiskCalculation)
            .where(RiskCalculation.subject_type == kind, RiskCalculation.subject_id == subject.id)
            .order_by(RiskCalculation.subject_revision.desc())
            .limit(limit + 1)
        )
    )
    return RiskHistory(
        current=current(db, subject),
        history=[calculation_view(row) for row in rows[:limit]],
        history_truncated=len(rows) > limit,
    )


def score_subject(
    db: Session,
    subject: Alert | Incident,
    *,
    request_id: str,
    actor_id: UUID | None = None,
    trigger: str = "evidence_changed",
) -> RiskCalculation:
    db.flush()
    kind: Literal["alert", "incident"] = "alert" if isinstance(subject, Alert) else "incident"
    alerts = (
        [subject]
        if isinstance(subject, Alert)
        else list(
            db.scalars(
                select(Alert)
                .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
                .where(IncidentAlert.incident_id == subject.id, IncidentAlert.active.is_(True))
                .order_by(Alert.id)
            )
        )
    )
    data, snapshot = build_input(
        alerts,
        subject_id=subject.id,
        mode=subject.mode,
        dataset_id=subject.dataset_id,
        run_id=subject.run_id,
        exclude_false_positive=kind == "incident",
        db=db,
    )
    input_hash = hashlib.sha256(canonical_json(snapshot)).hexdigest()
    intelligence = engine_v4.uses_intelligence(data)
    policy_hash = engine_v4.POLICY_HASH if intelligence else POLICY_HASH
    policy_version = engine_v4.POLICY_VERSION if intelligence else POLICY_VERSION
    prior = (
        db.get(RiskCalculation, subject.risk_calculation_id)
        if subject.risk_calculation_id
        else None
    )
    if prior is not None and prior.policy_hash == policy_hash and prior.input_sha256 == input_hash:
        return prior
    revision = (
        int(
            db.scalar(
                select(func.max(RiskCalculation.subject_revision)).where(
                    RiskCalculation.subject_type == kind, RiskCalculation.subject_id == subject.id
                )
            )
            or 0
        )
        + 1
    )
    result = engine_v4.calculate(data) if intelligence else calculate(data)
    row = RiskCalculation(
        id=uuid4(),
        subject_type=kind,
        subject_id=subject.id,
        subject_revision=revision,
        actor_id=actor_id,
        trigger=trigger,
        previous_id=prior.id if prior else None,
        policy_version=policy_version,
        policy_hash=policy_hash,
        input_sha256=input_hash,
        input_snapshot=snapshot,
        explanation=result.model_dump(mode="json"),
        score=result.score,
        level=result.level,
        mode=subject.mode,
        dataset_id=subject.dataset_id,
        run_id=subject.run_id,
    )
    db.add(row)
    db.flush()
    db.execute(text("SELECT public.aegis_apply_risk(:id)"), {"id": row.id})
    # SQL score projection must not become an ORM analyst update/version change.
    set_committed_value(subject, "risk_score", row.score)
    set_committed_value(subject, "risk_level", row.level)
    set_committed_value(subject, "risk_calculation_id", row.id)
    append_audit(
        db,
        action="risk.calculated",
        outcome="success",
        request_id=request_id,
        actor_id=actor_id,
        object_type=kind,
        object_id=str(subject.id),
        details={
            "calculation_id": str(row.id),
            "subject_revision": revision,
            "policy_version": policy_version,
            "input_sha256": input_hash,
            "score": row.score,
            "previous_score": prior.score if prior else None,
            "trigger": trigger,
        },
    )
    return row


def score_linked_incidents(db: Session, alert: Alert, *, request_id: str, actor_id: UUID) -> None:
    # All mutation callers hold the organization authority lock before row locks.
    identifiers = list(
        db.scalars(
            select(IncidentAlert.incident_id)
            .where(IncidentAlert.alert_id == alert.id, IncidentAlert.active.is_(True))
            .order_by(IncidentAlert.incident_id)
        )
    )
    for identifier in identifiers:
        incident = db.scalar(
            select(Incident)
            .where(Incident.id == identifier)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        assert incident is not None
        score_subject(
            db,
            incident,
            request_id=request_id,
            actor_id=actor_id,
            trigger="alert_disposition_changed",
        )


def backfill(db: Session, limit: int, *, request_id: str, actor_id: UUID) -> dict[str, Any]:
    counts = {"alerts": 0, "incidents": 0}
    for kind, model in (("alerts", Alert), ("incidents", Incident)):
        remaining_budget = limit - sum(counts.values())
        if remaining_budget <= 0:
            break
        rows = list(
            db.scalars(
                select(model)
                .where(model.risk_calculation_id.is_(None))
                .order_by(model.created_at, model.id)
                .limit(remaining_budget)
                .with_for_update()
            )
        )
        for row in rows:
            score_subject(
                db,
                cast(Alert | Incident, row),
                request_id=request_id,
                actor_id=actor_id,
                trigger="historical_backfill",
            )
            counts[kind] += 1
    remaining = sum(
        int(
            db.scalar(
                select(func.count()).select_from(model).where(model.risk_calculation_id.is_(None))
            )
            or 0
        )
        for model in (Alert, Incident)
    )
    return {**counts, "remaining": remaining, "policy_version": POLICY_VERSION}
