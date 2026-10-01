"""Evidence-preserving alert reads and audited, versioned analyst decisions."""

import base64
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from sqlalchemy import func, select, tuple_

from app.api.dependencies import DB, Principal, lock_authority, require
from app.core.errors import ApiError
from app.core.permissions import Permission
from app.core.rate_limit import rate_limit
from app.core.security import utcnow
from app.modules.alerts.models import Alert
from app.modules.alerts.schemas import (
    AlertDetail,
    AlertFilters,
    AlertList,
    AlertPatch,
    AlertSummary,
)
from app.modules.audit.service import append_audit
from app.modules.ingestion.schemas import canonical_json

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])
Reader = Annotated[Principal, Depends(require(Permission.ALERTS_READ))]
Analyst = Annotated[Principal, Depends(require(Permission.ALERTS_MANAGE))]


def _scope(data: AlertFilters, principal: Principal) -> str:
    value = data.model_dump(mode="json", exclude={"cursor"})
    value["user_id"] = str(principal.user.id)
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _cursor_key(request: Request) -> bytes:
    return hmac.digest(
        request.app.state.settings.jwt_secret.get_secret_value().encode(),
        b"aegis-alert-cursor-v1",
        "sha256",
    )


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _cursor(
    data: AlertFilters, request: Request, principal: Principal
) -> tuple[datetime, tuple[datetime, UUID] | None]:
    if data.cursor is None:
        return utcnow(), None
    try:
        parts = data.cursor.split(".")
        if len(parts) != 2:
            raise ValueError
        payload, signature = (_decode(part) for part in parts)
        if not hmac.compare_digest(signature, hmac.digest(_cursor_key(request), payload, "sha256")):
            raise ValueError
        content = json.loads(payload)
        if (
            set(content) != {"scope", "anchor", "time", "id", "expires", "v"}
            or content["v"] != 1
            or type(content["expires"]) is not int
            or content["expires"] < int(time.time())
            or content["scope"] != _scope(data, principal)
        ):
            raise ValueError
        anchor, after = (datetime.fromisoformat(content[key]) for key in ("anchor", "time"))
        if (
            any(
                value.tzinfo is None or value.utcoffset() != timedelta(0)
                for value in (anchor, after)
            )
            or after > anchor
        ):
            raise ValueError
        return anchor, (after, UUID(content["id"]))
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        raise ApiError(422, "invalid_cursor", "Alert cursor is invalid") from None


def _next_cursor(
    data: AlertFilters, request: Request, principal: Principal, anchor: datetime, last: Alert
) -> str:
    payload = canonical_json(
        {
            "v": 1,
            "scope": _scope(data, principal),
            "anchor": anchor.isoformat(),
            "time": last.created_at.astimezone(UTC).isoformat(),
            "id": str(last.id),
            "expires": int(time.time()) + 900,
        }
    )
    return _encode(payload) + "." + _encode(hmac.digest(_cursor_key(request), payload, "sha256"))


@router.get("", response_model=AlertList)
def list_alerts(
    data: Annotated[AlertFilters, Query()],
    request: Request,
    response: Response,
    db: DB,
    principal: Reader,
) -> AlertList:
    rate_limit(request, "alert-list", str(principal.user.id), 60, window_seconds=60)
    response.headers["Cache-Control"] = "no-store"
    anchor, after = _cursor(data, request, principal)
    filters = [Alert.created_at <= anchor]
    for name in ("status", "severity", "mode", "dataset_id", "source_id", "run_id"):
        value = getattr(data, name)
        if value is not None:
            filters.append(getattr(Alert, name) == value)
    total = int(db.scalar(select(func.count()).select_from(Alert).where(*filters)) or 0)
    query = (
        select(Alert)
        .where(*filters)
        .order_by(Alert.created_at.desc(), Alert.id.desc())
        .limit(data.limit + 1)
    )
    if after is not None:
        query = query.where(tuple_(Alert.created_at, Alert.id) < after)
    records = list(db.scalars(query))
    cursor = (
        _next_cursor(data, request, principal, anchor, records[data.limit - 1])
        if len(records) > data.limit
        else None
    )
    return AlertList(
        items=[AlertSummary.model_validate(row) for row in records[: data.limit]],
        total=total,
        next_cursor=cursor,
    )


@router.get("/{alert_id}", response_model=AlertDetail)
def alert_detail(alert_id: UUID, response: Response, db: DB, principal: Reader) -> AlertDetail:
    row = db.get(Alert, alert_id)
    if row is None:
        raise ApiError(404, "alert_not_found", "Alert not found")
    response.headers["Cache-Control"] = "no-store"
    response.headers["ETag"] = f'"{row.version}"'
    return AlertDetail.model_validate(row)


@router.patch("/{alert_id}", response_model=AlertDetail)
def update_alert(
    alert_id: UUID,
    data: AlertPatch,
    request: Request,
    response: Response,
    db: DB,
    principal: Analyst,
    if_match: Annotated[str | None, Header()] = None,
) -> AlertDetail:
    if if_match is None:
        raise ApiError(428, "version_required", "If-Match is required")
    lock_authority(db, principal, Permission.ALERTS_MANAGE, request)
    row = db.scalar(
        select(Alert)
        .where(Alert.id == alert_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if row is None:
        raise ApiError(404, "alert_not_found", "Alert not found")
    if if_match != f'"{row.version}"':
        raise ApiError(412, "version_conflict", "Refresh the alert before updating")
    if row.status == data.status:
        raise ApiError(409, "status_unchanged", "Alert already has this status")
    previous = row.status
    now = utcnow()
    row.status = data.status
    row.updated_at = now
    row.updated_by = principal.user.id
    if data.status == "acknowledged" and row.acknowledged_at is None:
        row.acknowledged_at = now
        row.acknowledged_by = principal.user.id
    append_audit(
        db,
        action="alert.status_changed",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=principal.user.id,
        object_type="alert",
        object_id=str(row.id),
        details={"before": previous, "after": data.status},
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["ETag"] = f'"{row.version}"'
    return AlertDetail.model_validate(row)
