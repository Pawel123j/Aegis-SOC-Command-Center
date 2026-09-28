"""Request scoped transactions and server-side authorization."""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import timedelta
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.core.errors import ApiError, unauthorized
from app.core.permissions import Permission, has_permission
from app.core.security import decode_access, utcnow
from app.modules.audit.service import append_audit
from app.modules.auth.models import AuthSession
from app.modules.users.models import User


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.database.sessions() as session:
        yield session


DB = Annotated[Session, Depends(get_db)]


@dataclass
class Principal:
    user: User
    session: AuthSession


def current_principal(request: Request, db: DB) -> Principal:
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer "):
        raise unauthorized()
    settings = request.app.state.settings
    identity = decode_access(settings, authorization[7:])
    auth_session = db.get(AuthSession, identity.session_id)
    user = db.get(User, identity.user_id)
    now = utcnow()
    if (
        not user
        or not user.enabled
        or not auth_session
        or auth_session.user_id != user.id
        or auth_session.revoked_at is not None
        or auth_session.absolute_expires_at <= now
        or auth_session.last_seen_at + timedelta(seconds=settings.session_idle_seconds) <= now
    ):
        raise unauthorized()
    return Principal(user, auth_session)


Current = Annotated[Principal, Depends(current_principal)]


def require(permission: Permission) -> Callable[..., Principal]:
    def check(request: Request, db: DB, principal: Current) -> Principal:
        if not has_permission(principal.user.role, permission):
            append_audit(
                db,
                action="authorization.denied",
                outcome="denied",
                request_id=request.state.request_id,
                actor_id=principal.user.id,
                details={"permission": permission.value},
            )
            db.commit()
            request.state.audit_recorded = True
            raise ApiError(403, "forbidden", "Permission denied")
        return principal

    return check
