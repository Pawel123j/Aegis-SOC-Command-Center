"""The local catalog is created only through a manager-authenticated test API."""

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.modules.audit.models import AuditLog
from app.modules.intelligence.models import IntEventMatch, IntEventReceipt, IOCIdentity, IOCRevision

from .helpers import Case, Login

BASE = "/api/v1/intelligence"


def create(
    principal: Login, value: str = "example.test", kind: str = "domain", **metadata: Any
) -> dict[str, Any]:
    response = principal.client.post(
        BASE + "/iocs",
        json={"type": kind, "value": value, "source": "Local test declaration", **metadata},
        headers=principal.authorization,
    )
    assert response.status_code == 201, response.text
    assert response.headers["etag"] == '"1"' and response.headers["cache-control"] == "no-store"
    return dict(response.json())


def counts(case: Case) -> dict[str, int]:
    with Session(case.database.runtime) as db:
        return {
            model.__tablename__: int(db.scalar(select(func.count()).select_from(model)) or 0)
            for model in (IOCIdentity, IOCRevision, IntEventReceipt, IntEventMatch, AuditLog)
        }
