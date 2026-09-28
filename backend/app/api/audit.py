"""Read-only audit API; no mutation routes exist."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.api.dependencies import DB, Principal, require
from app.core.permissions import Permission
from app.modules.audit.models import AuditLog

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("")
def audit(
    db: DB,
    principal: Annotated[Principal, Depends(require(Permission.AUDIT_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: UUID | None = None,
) -> dict[str, object]:
    query = select(AuditLog).order_by(AuditLog.id).limit(limit + 1)
    if cursor:
        query = query.where(AuditLog.id > cursor)
    records = list(db.scalars(query))
    return {
        "items": [
            {
                "id": row.id,
                "occurred_at": row.occurred_at,
                "actor_id": row.actor_id,
                "action": row.action,
                "outcome": row.outcome,
                "object_type": row.object_type,
                "object_id": row.object_id,
                "request_id": row.request_id,
                "details": row.details,
            }
            for row in records[:limit]
        ],
        "next_cursor": str(records[limit - 1].id) if len(records) > limit else None,
    }
