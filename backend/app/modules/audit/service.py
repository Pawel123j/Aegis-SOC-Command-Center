"""Audit participates in the caller's transaction; no hidden commits."""

import json
from uuid import UUID

from sqlalchemy.orm import Session

from app.modules.audit.models import AuditLog

_FORBIDDEN_KEYS = frozenset(
    {
        "password",
        "password_hash",
        "token",
        "access_token",
        "refresh_token",
        "csrf_token",
        "cookie",
        "authorization",
        "secret",
        "api_key",
        "credentials",
    }
)


def _validate_details(value: object, depth: int = 0) -> None:
    if depth > 5:
        raise ValueError("audit details nesting is too deep")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or key.lower() in _FORBIDDEN_KEYS:
                raise ValueError("audit details cannot contain credential fields")
            _validate_details(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _validate_details(item, depth + 1)


def append_audit(
    session: Session,
    *,
    action: str,
    outcome: str,
    request_id: str,
    actor_id: UUID | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    details: dict[str, object] | None = None,
) -> AuditLog:
    safe_details = details or {}
    _validate_details(safe_details)
    if len(json.dumps(safe_details, ensure_ascii=False).encode("utf-8")) > 8192:
        raise ValueError("audit details exceed the 8 KiB limit")
    record = AuditLog(
        action=action,
        outcome=outcome,
        request_id=request_id,
        actor_id=actor_id,
        object_type=object_type,
        object_id=object_id,
        details=safe_details,
    )
    session.add(record)
    session.flush()
    return record
