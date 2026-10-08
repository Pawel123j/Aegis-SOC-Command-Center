"""Closed local action implementations. This module has no network/command adapter."""

from ipaddress import ip_address
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.modules.alerts.models import Alert
from app.modules.incidents.models import Incident, IncidentAlert
from app.modules.incidents.schemas import IncidentCreate
from app.modules.incidents.service import create_incident, validate_scope
from app.modules.intelligence.models import IOCIdentity
from app.modules.intelligence.schemas import IOCInput
from app.modules.intelligence.service import create_ioc, current_revision
from app.modules.soar.models import PlaybookRun, PlaybookStep, SoarNotification
from app.modules.users.models import User


def execute_action(
    db: Session, run: PlaybookRun, step: PlaybookStep, alert: Alert, actor: User
) -> dict[str, Any]:
    context, action = run.context, step.action
    ip = context["ip"]
    base: dict[str, Any] = {"action": action, "action_version": "1", "status": "completed"}
    if action in {"enrich_ip", "add_ioc", "simulate_block_ip"} and ip is None:
        return {**base, "status": "not_applicable", "reason": "Brak wybranego IP w dowodzie."}
    if action == "enrich_ip":
        address = ip_address(ip)
        return {
            **base,
            "ip": str(address),
            "ip_version": address.version,
            "local_only": True,
            "reason": "Poprawny adres z dowodu. Bez DNS i usług online.",
        }
    if action == "check_threat_intelligence":
        return {
            **base,
            "proof": context["intelligence"],
            "ip": ip,
            "reason": "Przypięty wynik pierwszej analizy zdarzenia; brak analizy to pending.",
        }
    if action == "calculate_risk":
        return {
            **base,
            "risk": context["risk"],
            "status": "completed" if context["risk"] else "unavailable",
            "reason": (
                "Zachowana ocena alertu z wyjaśnieniem; bez uznaniowego podnoszenia wyniku."
                if context["risk"]
                else "Brak zachowanej oceny ryzyka dla tego alertu."
            ),
        }
    if action == "create_incident":
        # All case API mutations and SOAR actions hold ADMIN_LOCK_ID. Detection
        # creates its automatic case before its alert is visible to a SOAR start.
        incident = db.scalar(
            select(Incident)
            .join(IncidentAlert, IncidentAlert.incident_id == Incident.id)
            .where(
                IncidentAlert.alert_id == alert.id,
                IncidentAlert.active.is_(True),
                Incident.status.not_in(("resolved", "closed")),
            )
            .order_by(Incident.created_at, Incident.id)
            .limit(1)
            .with_for_update(of=Incident)
        )
        created = incident is None
        if incident is None:
            closed = db.scalar(
                select(Incident.id)
                .join(IncidentAlert, IncidentAlert.incident_id == Incident.id)
                .where(
                    IncidentAlert.alert_id == alert.id,
                    IncidentAlert.active.is_(True),
                    Incident.status.in_(("resolved", "closed")),
                )
                .limit(1)
            )
            previous = db.scalar(select(Incident).where(Incident.automatic_alert_id == alert.id))
            if previous is not None or closed is not None:
                raise ApiError(
                    409, "soar_incident_review_required", "Review the existing case first"
                )
            incident = create_incident(
                db,
                IncidentCreate(
                    title=alert.title,
                    description="Utworzono przez procedurę SOAR.",
                    alert_ids=[alert.id],
                ),
                request_id=str(run.id),
                actor=actor,
                automatic_alert_id=alert.id,
            )
        validate_scope(incident, alert)
        return {
            **base,
            "incident_id": str(incident.id),
            "created": created,
            "local_effect": True,
            "reason": "Sprawa zapisana w aplikacji.",
        }
    if action == "add_ioc":
        if run.mode == "replay":
            return {
                **base,
                "simulated": True,
                "ip": ip,
                "reason": f"SIMULATION: IP {ip} zostałby dodany do przeglądu IOC.",
            }
        existing = db.scalar(
            select(IOCIdentity).where(IOCIdentity.kind == "ip", IOCIdentity.canonical_value == ip)
        )
        if existing is not None:
            current_revision(db, existing)
            return {
                **base,
                "ioc_id": str(existing.id),
                "created": False,
                "reason": "IOC już istnieje; metadane pozostawiono do jawnego przeglądu.",
            }
        ioc, created = create_ioc(
            db,
            IOCInput(
                type="ip",
                value=ip,
                source="soar-review",
                active=False,
                description="Adres z dowodu alertu, do przeglądu przez analityka.",
            ),
            actor=actor.id,
            request_id=str(run.id),
        )
        return {
            **base,
            "ioc_id": str(ioc.id),
            "created": created,
            "active": False,
            "reputation": "unknown",
            "local_effect": True,
            "reason": "Nieaktywny IOC wymaga oceny i jawnego włączenia w Threat Intelligence.",
        }
    if action == "notify_analyst":
        notification = SoarNotification(
            id=uuid4(),
            step_id=step.id,
            recipient_id=actor.id,
            message=("Powtórzenie procedury: " if run.replay_of else "Procedura SOAR: ")
            + f"wykonano krok powiadomienia dla alertu {alert.id}.",
        )
        db.add(notification)
        return {
            **base,
            "notification_id": str(notification.id),
            "recipient_id": str(actor.id),
            "local_effect": True,
            "reason": "Powiadomienie zapisano w aplikacji.",
        }
    if action == "simulate_block_ip":
        return {
            **base,
            "simulated": True,
            "ip": ip,
            "reason": f"SIMULATION: IP {ip} zostałby zablokowany.",
        }
    if action == "simulate_isolate_host":
        host = context["host"]
        return {
            **base,
            "simulated": True,
            "host": host,
            "status": "completed" if host else "not_applicable",
            "reason": f"SIMULATION: komputer {host} zostałby odizolowany."
            if host
            else "Brak komputera w dowodzie; nie zaplanowano izolacji.",
        }
    if action == "simulate_webhook":
        return {
            **base,
            "simulated": True,
            "network_access": False,
            "reason": "SIMULATION: wysłano by powiadomienie webhook o tym wykonaniu. "
            "Brak skonfigurowanego odbiorcy.",
        }
    raise ApiError(409, "soar_action_unsupported", "Unsupported workflow action")
