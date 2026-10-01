"""Bounded case views use original immutable alert evidence."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.modules.alerts.evidence import contributors
from app.modules.alerts.models import Alert
from app.modules.alerts.schemas import AlertSummary
from app.modules.incidents.models import Incident, IncidentAlert, IncidentNote, IncidentTimeline
from app.modules.incidents.schemas import (
    Actor,
    EvidenceView,
    IncidentDetail,
    IncidentSummary,
    NoteView,
    TimelineView,
)
from app.modules.incidents.service import linked_alerts
from app.modules.users.models import User


def summary(db: Session, incident: Incident) -> IncidentSummary:
    result = IncidentSummary.model_validate(incident)
    owner = db.get(User, incident.owner_id) if incident.owner_id else None
    result.owner = Actor.model_validate(owner) if owner is not None else None
    return result


def detail(db: Session, incident: Incident) -> IncidentDetail:
    return IncidentDetail(
        **summary(db, incident).model_dump(),
        related_alerts=[
            AlertSummary.model_validate(alert) for alert in linked_alerts(db, incident)
        ],
        related_users=incident.related_users,
        related_hosts=incident.related_hosts,
        related_ip_addresses=incident.related_ip_addresses,
        mitre_techniques=incident.mitre_techniques,
        dataset_ids=incident.dataset_ids,
        evidence_count=int(
            db.scalar(
                select(func.count())
                .select_from(IncidentAlert)
                .where(IncidentAlert.incident_id == incident.id)
            )
            or 0
        ),
        notes=[
            NoteView.model_validate(row)
            for row in db.scalars(
                select(IncidentNote)
                .where(IncidentNote.incident_id == incident.id)
                .order_by(IncidentNote.created_at.desc(), IncidentNote.id.desc())
                .limit(50)
            )
        ],
        timeline=[
            TimelineView.model_validate(row)
            for row in db.scalars(
                select(IncidentTimeline)
                .where(IncidentTimeline.incident_id == incident.id)
                .order_by(IncidentTimeline.occurred_at.desc(), IncidentTimeline.id.desc())
                .limit(50)
            )
        ],
    )


def evidence(link: IncidentAlert, alert: Alert) -> EvidenceView:
    # The link is an immutable provenance reference; disposition does not alter the source alert.
    return EvidenceView(
        id=link.id,
        alert_id=alert.id,
        event_id=alert.event_id,
        source_id=alert.source_id,
        dataset_id=alert.dataset_id,
        mode=alert.mode,
        run_id=alert.run_id,
        event_timestamp=alert.event_timestamp,
        linked_at=link.linked_at,
        active=link.active,
        detached_at=link.detached_at,
        event_sha256=alert.event_sha256,
        rule_snapshot=alert.rule_snapshot,
        event_snapshot=alert.event_snapshot,
        event_snapshots=contributors(alert),
        reason=alert.reason,
    )
