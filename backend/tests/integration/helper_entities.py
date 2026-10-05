"""Profile fixtures use authentic ingestion and a fixed, explicit activity window."""

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.modules.entities.models import (
    AlertEventReference,
    EntityAlertReceipt,
    EntityIdentity,
    EntityIndexReceipt,
    EntityObservation,
)

from .helpers import Case, Login

WINDOW = {"from": "2026-10-01T00:00:00Z", "to": "2026-10-02T00:00:00Z"}


def read(admin: Login, path: str = "", **params: Any) -> dict[str, Any]:
    response = admin.client.get(
        f"/api/v1/entities{path}", params={**WINDOW, **params}, headers=admin.authorization
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    return dict(response.json())


def counts(case: Case) -> dict[str, int]:
    with Session(case.database.runtime) as db:
        return {
            model.__tablename__: int(db.scalar(select(func.count()).select_from(model)) or 0)
            for model in (
                EntityIdentity,
                EntityIndexReceipt,
                EntityObservation,
                EntityAlertReceipt,
                AlertEventReference,
            )
        }
