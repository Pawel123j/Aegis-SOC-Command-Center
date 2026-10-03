"""Case mutations share their transaction with timeline and immutable audit entries."""

import hashlib
import hmac
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.core.permissions import Permission, Role, has_permission
from app.infrastructure.database import utcnow
from app.modules.alerts.evidence import verified_events
from app.modules.alerts.models import Alert
from app.modules.audit.service import append_audit
from app.modules.incidents.models import Incident, IncidentAlert, IncidentNote, IncidentTimeline
from app.modules.incidents.schemas import IncidentCreate, IncidentPatch
from app.modules.ingestion.models import LIVE_RUN_ID
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.schemas import canonical_ip
from app.modules.risk.service import score_subject
from app.modules.users.models import User

SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
OWNER_ROLES = (Role.ADMIN, Role.SOC_MANAGER, Role.SOC_ANALYST)
STATUS_TRANSITIONS = {
    "new": frozenset({"investigating", "resolved"}),
    "investigating": frozenset({"contained", "resolved"}),
    "contained": frozenset({"investigating", "resolved"}),
    "resolved": frozenset({"closed", "investigating"}),
    "closed": frozenset({"investigating"}),
}


def actor_snapshot(actor: User | None) -> dict[str, Any] | None:
    return (
        {"id": str(actor.id), "username": actor.username, "role": actor.role.value}
        if actor
        else None
    )


def record_change(
    db: Session,
    incident: Incident,
    kind: str,
    data: dict[str, Any],
    *,
    request_id: str,
    actor: User | None,
    now: datetime | None = None,
) -> None:
    timeline_id = uuid4()
    db.add(
        IncidentTimeline(
            id=timeline_id,
            incident_id=incident.id,
            kind=kind,
            data=data,
            occurred_at=now or utcnow(),
            actor_id=actor.id if actor else None,
            actor=actor_snapshot(actor),
        )
    )
    action = "incident.created" if kind == "incident_created" else f"incident.{kind}"
    audit_details = dict(data)
    if kind == "note_added":
        audit_details = {
            "note_id": data["note_id"],
            "body_sha256": hashlib.sha256(data["body"].encode()).hexdigest(),
            "body_chars": len(data["body"]),
        }
    elif kind == "fields_updated":
        audit_details = {
            "changed_fields": sorted(data["after"]),
            **{
                f"{key}_sha256": hashlib.sha256(canonical_json(data[key])).hexdigest()
                for key in ("before", "after")
            },
        }
    audit_details["timeline_id"] = str(timeline_id)
    append_audit(
        db,
        action=action,
        outcome="success",
        request_id=request_id,
        actor_id=actor.id if actor else None,
        object_type="incident",
        object_id=str(incident.id),
        details=audit_details,
    )


def validate_scope(incident: Incident, alert: Alert) -> None:
    if (
        alert.mode != incident.mode
        or alert.run_id != incident.run_id
        or (incident.mode == "replay" and alert.dataset_id != incident.dataset_id)
    ):
        raise ApiError(409, "incident_scope_mismatch", "Alert and incident scopes must match")


def linked_alerts(db: Session, incident: Incident) -> list[Alert]:
    return list(
        db.scalars(
            select(Alert)
            .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
            .where(IncidentAlert.incident_id == incident.id, IncidentAlert.active.is_(True))
            .order_by(Alert.event_timestamp, Alert.id)
        )
    )


def recompute_entities(db: Session, incident: Incident) -> None:
    db.flush()
    alerts = linked_alerts(db, incident)
    incident.alert_count = len(alerts)
    all_events = [event for alert in alerts for event in verified_events(alert)]
    incident.first_seen = min((event.timestamp for event in all_events), default=None)
    incident.last_seen = max((event.timestamp for event in all_events), default=None)
    users: set[str] = set()
    hosts: set[str] = set()
    ips: set[str] = set()
    mitre: set[str] = set()
    for event in all_events:
        for account in (event.user, event.user.target):
            if account.name:
                users.add(f"{account.realm}\\{account.name}" if account.realm else account.name)
            elif account.id:
                users.add(account.id)
        if event.host.name or event.host.id:
            hosts.add(event.host.name or event.host.id or "")
        for address in (event.source.ip, event.destination.ip):
            if address is not None:
                # Serialization preserves the same IPv4-mapped IPv6 representation as event search.
                ips.add(canonical_ip(address))
    for alert in alerts:
        mitre.update(
            value for value in alert.rule_snapshot.get("mitre", []) if isinstance(value, str)
        )
    incident.related_users = sorted(users)
    incident.related_hosts = sorted(hosts)
    incident.related_ip_addresses = sorted(ips)
    incident.mitre_techniques = sorted(mitre)
    incident.dataset_ids = sorted({str(event.dataset_id) for event in all_events})


def touch(incident: Incident, actor: User | None) -> None:
    incident.updated_at = utcnow()
    incident.updated_by = actor.id if actor else None


def ensure_open(incident: Incident) -> None:
    if incident.status == "closed":
        raise ApiError(409, "incident_closed", "Reopen the incident before editing")


def attach_alert(
    db: Session,
    incident: Incident,
    alert: Alert,
    *,
    request_id: str,
    actor: User | None,
    aggregate: bool = True,
) -> None:
    ensure_open(incident)
    validate_scope(incident, alert)
    if not hmac.compare_digest(
        hashlib.sha256(canonical_json(alert.event_snapshot)).hexdigest(), alert.event_sha256
    ):
        raise ApiError(409, "evidence_integrity_mismatch", "Alert evidence integrity failed")
    try:
        verified_events(alert)
    except (KeyError, TypeError, ValueError):
        raise ApiError(
            409, "evidence_integrity_mismatch", "Alert evidence integrity failed"
        ) from None
    existing = db.scalar(
        select(IncidentAlert).where(
            IncidentAlert.incident_id == incident.id,
            IncidentAlert.alert_id == alert.id,
        )
    )
    if existing is not None and existing.active:
        raise ApiError(409, "alert_already_attached", "Alert is already attached")
    active_count = int(
        db.scalar(
            select(func.count())
            .select_from(IncidentAlert)
            .where(
                IncidentAlert.incident_id == incident.id,
                IncidentAlert.active.is_(True),
            )
        )
        or 0
    )
    if active_count >= 100:
        raise ApiError(409, "incident_alert_limit", "Incident supports at most 100 active alerts")
    if existing is None:
        db.add(
            IncidentAlert(
                incident_id=incident.id, alert_id=alert.id, linked_by=actor.id if actor else None
            )
        )
    else:
        existing.active = True
        existing.detached_at = None
        existing.detached_by = None
    record_change(
        db,
        incident,
        "alert_attached",
        {
            "alert_id": str(alert.id),
            "event_id": str(alert.event_id),
            "title": alert.title,
            "event_timestamp": alert.event_timestamp.isoformat(),
            "event_sha256": alert.event_sha256,
        },
        request_id=request_id,
        actor=actor,
    )
    if aggregate:
        recompute_entities(db, incident)
        touch(incident, actor)
        score_subject(db, incident, request_id=request_id, actor_id=actor.id if actor else None)
    else:
        db.flush()


def detach_alert(
    db: Session,
    incident: Incident,
    alert_id: UUID,
    *,
    request_id: str,
    actor: User,
) -> None:
    ensure_open(incident)
    link = db.scalar(
        select(IncidentAlert).where(
            IncidentAlert.incident_id == incident.id,
            IncidentAlert.alert_id == alert_id,
            IncidentAlert.active.is_(True),
        )
    )
    alert = db.get(Alert, alert_id)
    if link is None or alert is None:
        raise ApiError(404, "attachment_not_found", "Attached alert not found")
    link.active = False
    link.detached_at = utcnow()
    link.detached_by = actor.id
    record_change(
        db,
        incident,
        "alert_detached",
        {
            "alert_id": str(alert.id),
            "event_id": str(alert.event_id),
            "title": alert.title,
            "event_timestamp": alert.event_timestamp.isoformat(),
            "event_sha256": alert.event_sha256,
        },
        request_id=request_id,
        actor=actor,
    )
    recompute_entities(db, incident)
    touch(incident, actor)
    score_subject(db, incident, request_id=request_id, actor_id=actor.id)


def create_incident(
    db: Session,
    data: IncidentCreate,
    *,
    request_id: str,
    actor: User | None,
    automatic_alert_id: UUID | None = None,
) -> Incident:
    alerts = [db.get(Alert, identifier) for identifier in data.alert_ids]
    if any(alert is None for alert in alerts):
        raise ApiError(404, "alert_not_found", "Alert not found")
    first = alerts[0] if alerts else None
    mode = data.mode or (first.mode if first is not None else "live")
    dataset = data.dataset_id or (
        first.dataset_id if first is not None and mode == "replay" else None
    )
    run = data.run_id or (first.run_id if first is not None else LIVE_RUN_ID)
    if (mode == "live" and (dataset is not None or run != LIVE_RUN_ID)) or (
        mode == "replay" and (dataset is None or run == LIVE_RUN_ID)
    ):
        raise ApiError(
            422, "invalid_incident_scope", "Live and replay incident scopes are distinct"
        )
    highest = max(
        (alert.severity for alert in alerts if alert is not None),
        key=SEVERITY_ORDER.__getitem__,
        default="low",
    )
    severity = data.severity or ("low" if highest == "informational" else highest)
    incident = Incident(
        id=uuid4(),
        automatic_alert_id=automatic_alert_id,
        title=data.title,
        description=data.description,
        severity=severity,
        status="new",
        mode=mode,
        dataset_id=dataset,
        run_id=run,
        created_by=actor.id if actor else None,
        updated_by=actor.id if actor else None,
        tags=data.tags,
        risk_score=None,
        confidence=None,
    )
    db.add(incident)
    db.flush()
    record_change(
        db,
        incident,
        "incident_created",
        {
            "automatic": automatic_alert_id is not None,
            "alert_ids": [str(value) for value in data.alert_ids],
        },
        request_id=request_id,
        actor=actor,
    )
    for alert in alerts:
        assert alert is not None
        attach_alert(db, incident, alert, request_id=request_id, actor=actor, aggregate=False)
    if alerts:
        recompute_entities(db, incident)
        touch(incident, actor)
    score_subject(
        db,
        incident,
        request_id=request_id,
        actor_id=actor.id if actor else None,
        trigger="incident_created",
    )
    db.flush()
    return incident


def automatic_incident(db: Session, alert: Alert, *, request_id: str) -> Incident | None:
    """One distinct case for each new High/Critical alert; this is not correlation."""
    if alert.severity not in {"high", "critical"}:
        return None
    existing = db.scalar(select(Incident).where(Incident.automatic_alert_id == alert.id))
    if existing is not None:
        return existing
    return create_incident(
        db,
        IncidentCreate(
            title=alert.title,
            description=(
                "Incydent utworzony automatycznie z alertu High/Critical. Wymaga oceny analityka."
            ),
            alert_ids=[alert.id],
        ),
        request_id=request_id,
        actor=None,
        automatic_alert_id=alert.id,
    )


def patch_incident(
    db: Session,
    incident: Incident,
    data: IncidentPatch,
    *,
    request_id: str,
    actor: User,
) -> None:
    fields = data.model_fields_set - {"status_reason"}
    if data.status is not None and data.status != incident.status:
        if data.status not in STATUS_TRANSITIONS[incident.status]:
            raise ApiError(
                409, "invalid_incident_transition", "Incident status transition is invalid"
            )
        if incident.status in {"resolved", "closed"} and data.status == "investigating":
            if not has_permission(actor.role, Permission.INCIDENTS_REOPEN):
                raise ApiError(403, "forbidden", "Permission denied")
            if not data.status_reason:
                raise ApiError(422, "status_reason_required", "A status reason is required")
    if incident.status == "closed":
        if fields != {"status"} or data.status != "investigating":
            raise ApiError(
                409, "incident_closed", "Closed incidents can only be reopened to investigating"
            )
        if not has_permission(actor.role, Permission.INCIDENTS_REOPEN):
            raise ApiError(403, "forbidden", "Permission denied")
    if data.status == "closed" and not has_permission(actor.role, Permission.INCIDENTS_CLOSE):
        raise ApiError(403, "forbidden", "Permission denied")
    if data.status in {"contained", "resolved", "closed"} or incident.status == "closed":
        if not data.status_reason:
            raise ApiError(422, "status_reason_required", "A status reason is required")
    changes = {
        key: getattr(data, key) for key in fields if getattr(data, key) != getattr(incident, key)
    }
    if not changes:
        raise ApiError(409, "incident_unchanged", "Incident fields are unchanged")
    if "owner_id" in changes:
        owner_id = data.owner_id
        if not has_permission(actor.role, Permission.INCIDENTS_ASSIGN_ANY) and (
            not has_permission(actor.role, Permission.INCIDENTS_ASSIGN_SELF)
            or (owner_id is not None and owner_id != actor.id)
            or (owner_id is None and incident.owner_id != actor.id)
        ):
            raise ApiError(403, "forbidden", "Permission denied")
        owner = db.get(User, owner_id) if owner_id is not None else None
        if owner_id is not None and (
            owner is None or not owner.enabled or owner.role not in OWNER_ROLES
        ):
            raise ApiError(422, "invalid_incident_owner", "Owner must be an enabled SOC analyst")
    ordinary = {key: value for key, value in changes.items() if key not in {"status", "owner_id"}}
    if ordinary:
        record_change(
            db,
            incident,
            "fields_updated",
            {
                "before": {key: getattr(incident, key) for key in ordinary},
                "after": ordinary,
            },
            request_id=request_id,
            actor=actor,
        )
    for key, value in changes.items():
        if key in {"status", "owner_id"}:
            before = getattr(incident, key)
            event = {
                "before": str(before) if isinstance(before, UUID) else before,
                "after": str(value) if isinstance(value, UUID) else value,
            }
            if key == "status":
                event["reason"] = data.status_reason
            record_change(
                db,
                incident,
                "status_changed" if key == "status" else "owner_changed",
                event,
                request_id=request_id,
                actor=actor,
            )
    # Audit flushes must not expose a partial multi-field decision or increment
    # the optimistic version more than once for one analyst mutation.
    for key, value in changes.items():
        setattr(incident, key, value)
    touch(incident, actor)


def add_note(db: Session, incident: Incident, body: str, *, request_id: str, actor: User) -> None:
    snapshot = actor_snapshot(actor)
    assert snapshot is not None
    note = IncidentNote(
        id=uuid4(), incident_id=incident.id, body=body, author_id=actor.id, author=snapshot
    )
    db.add(note)
    record_change(
        db,
        incident,
        "note_added",
        {"note_id": str(note.id), "body": body},
        request_id=request_id,
        actor=actor,
    )
    touch(incident, actor)
