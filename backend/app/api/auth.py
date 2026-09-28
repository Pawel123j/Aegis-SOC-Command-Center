"""Browser authentication: origin + synchronizer CSRF + persisted rotation."""

from datetime import timedelta

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy import delete, select

from app.api.dependencies import DB, Current
from app.core.errors import ApiError, unauthorized
from app.core.permissions import permissions_for
from app.core.rate_limit import peer, rate_limit
from app.core.security import (
    DUMMY_HASH,
    PASSWORD_HASHER,
    hash_password,
    random_token,
    session_csrf,
    token_hash,
    utcnow,
    verify_password,
)
from app.modules.audit.service import append_audit
from app.modules.auth.models import PreAuthSession
from app.modules.auth.service import (
    cookie_name,
    find_refresh,
    issue_tokens,
    new_session,
    require_csrf,
    require_origin,
    set_cookie,
    usable_session,
)
from app.modules.users.models import User, normalize_username

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64)
    password: SecretStr = Field(min_length=15, max_length=128)

    @field_validator("username")
    @classmethod
    def normalized(cls, value: str) -> str:
        return normalize_username(value)


@router.get("/csrf")
def csrf(request: Request, response: Response, db: DB) -> dict[str, str]:
    settings = request.app.state.settings
    rate_limit(request, "csrf", peer(request), 30)
    response.headers["Cache-Control"] = "no-store"
    if request.cookies.get(cookie_name(settings, "refresh")):
        try:
            family, refresh = find_refresh(db, request)
            usable_session(db, family, settings)
            if refresh.used_at is None and refresh.expires_at > utcnow():
                return {"csrf_token": session_csrf(settings, family.id)}
        except ApiError:
            pass
        response.delete_cookie(cookie_name(settings, "refresh"), path="/api/v1/auth")
    raw, csrf_value = random_token(), random_token()
    now = utcnow()
    # Bound housekeeping work; expired pre-auth rows confer no authentication authority.
    expired = select(PreAuthSession.token_hash).where(PreAuthSession.expires_at <= now).limit(1000)
    db.execute(delete(PreAuthSession).where(PreAuthSession.token_hash.in_(expired)))
    db.add(
        PreAuthSession(
            token_hash=token_hash(raw),
            csrf_token_hash=token_hash(csrf_value),
            created_at=now,
            expires_at=now + timedelta(seconds=settings.preauth_seconds),
        )
    )
    db.commit()
    set_cookie(response, settings, "preauth", raw, settings.preauth_seconds)
    return {"csrf_token": csrf_value}


@router.post("/login")
def login(data: LoginInput, request: Request, response: Response, db: DB) -> dict[str, str | int]:
    settings = request.app.state.settings
    require_origin(request, settings)
    rate_limit(request, "login-ip", peer(request), 30)
    rate_limit(request, "login-account", f"{peer(request)}:{data.username}", 5)
    raw = request.cookies.get(cookie_name(settings, "preauth"), "")
    if not raw or len(raw) > 128:
        raise ApiError(403, "csrf_failed", "Origin or CSRF token invalid")
    preauth = db.scalar(
        select(PreAuthSession).where(PreAuthSession.token_hash == token_hash(raw)).with_for_update()
    )
    if preauth is None or preauth.used_at is not None or preauth.expires_at <= utcnow():
        raise ApiError(403, "csrf_failed", "Origin or CSRF token invalid")
    require_csrf(request, preauth.csrf_token_hash)
    user = db.scalar(select(User).where(User.username == data.username).with_for_update())
    valid = verify_password(
        data.password.get_secret_value(), user.password_hash if user else DUMMY_HASH
    )
    preauth.used_at = utcnow()
    if not user or not valid or not user.enabled:
        append_audit(
            db,
            action="auth.login",
            outcome="denied",
            request_id=request.state.request_id,
            details={"account_hash": token_hash(data.username)},
        )
        db.commit()
        request.state.audit_recorded = True
        raise unauthorized()
    if PASSWORD_HASHER.check_needs_rehash(user.password_hash):
        user.password_hash = hash_password(data.password.get_secret_value())
    family = new_session(db, user, settings)
    result = issue_tokens(db, family, response, settings)
    append_audit(
        db,
        action="auth.login",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=user.id,
    )
    db.commit()
    response.delete_cookie(cookie_name(settings, "preauth"), path="/api/v1/auth")
    return result


@router.post("/refresh")
def refresh(request: Request, response: Response, db: DB) -> dict[str, str | int]:
    settings = request.app.state.settings
    require_origin(request, settings)
    rate_limit(request, "refresh-ip", peer(request), 60)
    family, stored = find_refresh(db, request)
    require_csrf(request, family.csrf_token_hash)
    rate_limit(request, "refresh-family", str(family.id), 30)
    if stored.used_at is not None:
        family.revoked_at = utcnow()
        append_audit(
            db,
            action="auth.refresh_reuse",
            outcome="revoked",
            request_id=request.state.request_id,
            actor_id=family.user_id,
        )
        db.commit()
        request.state.audit_recorded = True
        raise unauthorized()
    user = usable_session(db, family, settings)
    if stored.expires_at <= utcnow():
        raise unauthorized()
    stored.used_at = utcnow()
    family.last_seen_at = utcnow()
    result = issue_tokens(db, family, response, settings)
    append_audit(
        db,
        action="auth.refresh",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=user.id,
    )
    db.commit()
    return result


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db: DB) -> None:
    settings = request.app.state.settings
    require_origin(request, settings)
    rate_limit(request, "logout", peer(request), 30)
    family, _ = find_refresh(db, request)
    require_csrf(request, family.csrf_token_hash)
    family.revoked_at = utcnow()
    append_audit(
        db,
        action="auth.logout",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=family.user_id,
    )
    db.commit()
    response.delete_cookie(cookie_name(settings, "refresh"), path="/api/v1/auth")
    response.headers["Cache-Control"] = "no-store"


@router.get("/me")
def me(response: Response, principal: Current) -> dict[str, object]:
    response.headers["Cache-Control"] = "no-store"
    return {
        "id": str(principal.user.id),
        "username": principal.user.username,
        "role": principal.user.role.value,
        "permissions": sorted(p.value for p in permissions_for(principal.user.role)),
    }
