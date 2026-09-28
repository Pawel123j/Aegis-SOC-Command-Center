"""Persistent session operations shared by the auth routes."""

import hmac
from datetime import timedelta
from uuid import uuid4

from fastapi import Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import ApiError, unauthorized
from app.core.security import access_token, random_token, session_csrf, token_hash, utcnow
from app.modules.auth.models import AuthSession, RefreshToken
from app.modules.users.models import User


def cookie_name(settings: Settings, kind: str) -> str:
    return settings.refresh_cookie_name if kind == "refresh" else settings.preauth_cookie_name


def set_cookie(response: Response, settings: Settings, kind: str, value: str, age: int) -> None:
    response.set_cookie(
        cookie_name(settings, kind),
        value,
        max_age=age,
        httponly=True,
        secure=not settings.local_http,
        samesite="strict",
        path="/api/v1/auth",
    )
    response.headers["Cache-Control"] = "no-store"


def require_origin(request: Request, settings: Settings) -> None:
    if request.headers.get("origin") != settings.public_origin:
        raise ApiError(403, "csrf_failed", "Origin or CSRF token invalid")


def require_csrf(request: Request, expected_hash: str) -> None:
    supplied = request.headers.get("x-csrf-token", "")
    if (
        len(supplied) > 256
        or not supplied
        or not hmac.compare_digest(token_hash(supplied), expected_hash)
    ):
        raise ApiError(403, "csrf_failed", "Origin or CSRF token invalid")


def find_refresh(db: Session, request: Request) -> tuple[AuthSession, RefreshToken]:
    settings = request.app.state.settings
    raw = request.cookies.get(cookie_name(settings, "refresh"), "")
    if not raw or len(raw) > 128:
        raise unauthorized()
    stored = db.get(RefreshToken, token_hash(raw))
    if stored is None:
        raise unauthorized()
    # Lock the family first: two different tokens in the same family also serialize.
    family = db.scalar(
        select(AuthSession).where(AuthSession.id == stored.session_id).with_for_update()
    )
    if family is None:
        raise unauthorized()
    db.refresh(stored)
    return family, stored


def usable_session(db: Session, family: AuthSession, settings: Settings) -> User:
    user = db.get(User, family.user_id)
    if (
        not user
        or not user.enabled
        or family.revoked_at
        or family.absolute_expires_at <= utcnow()
        or family.last_seen_at + timedelta(seconds=settings.session_idle_seconds) <= utcnow()
    ):
        raise unauthorized()
    return user


def new_session(db: Session, user: User, settings: Settings) -> AuthSession:
    now, session_id = utcnow(), uuid4()
    family = AuthSession(
        id=session_id,
        user_id=user.id,
        created_at=now,
        last_seen_at=now,
        absolute_expires_at=now + timedelta(seconds=settings.session_absolute_seconds),
        csrf_token_hash=token_hash(session_csrf(settings, session_id)),
    )
    db.add(family)
    db.flush()
    return family


def issue_tokens(
    db: Session, family: AuthSession, response: Response, settings: Settings
) -> dict[str, str | int]:
    raw = random_token()
    now = utcnow()
    db.add(
        RefreshToken(
            token_hash=token_hash(raw),
            session_id=family.id,
            created_at=now,
            expires_at=family.absolute_expires_at,
        )
    )
    set_cookie(
        response,
        settings,
        "refresh",
        raw,
        max(0, int((family.absolute_expires_at - now).total_seconds())),
    )
    return {
        "access_token": access_token(settings, family.user_id, family.id),
        "token_type": "bearer",
        "expires_in": settings.access_token_seconds,
        "csrf_token": session_csrf(settings, family.id),
    }
