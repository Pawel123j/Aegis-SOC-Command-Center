"""Timeline fixtures reuse genuine intake, detection and incident mutations."""

from typing import Any
from uuid import UUID

from app.modules.detections.processing import process_once as detect_once

from .helper_ingestion import processing_database
from .helpers import Case, Login
from .test_incidents import create
from .test_initial_alerts import alerts, normalize_events


def seed(case: Case, admin: Login, events: list[dict[str, Any]]) -> list[UUID]:
    ids = normalize_events(case, admin, events)
    detect_once(processing_database(case), case.database.settings)
    return [row.id for row in alerts(case) if row.event_id in ids]


def attach(admin: Login, incident: dict[str, Any], alert_id: UUID) -> dict[str, Any]:
    response = admin.client.post(
        f"/api/v1/incidents/{incident['id']}/alerts",
        json={"alert_id": str(alert_id)},
        headers={**admin.authorization, "If-Match": f'"{incident["version"]}"'},
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


def read(admin: Login, incident_id: str | UUID, **params: Any) -> dict[str, Any]:
    response = admin.client.get(
        f"/api/v1/incidents/{incident_id}/attack-timeline",
        params=params,
        headers=admin.authorization,
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    return dict(response.json())


__all__ = ["attach", "create", "read", "seed"]
