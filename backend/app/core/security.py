"""Hashing and tightly scoped access tokens; never log inputs or library errors."""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.config import Settings
from app.core.errors import unauthorized

PASSWORD_HASHER = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
DUMMY_HASH = PASSWORD_HASHER.hash(secrets.token_urlsafe(32))


def utcnow() -> datetime:
    return datetime.now(UTC)


def hash_password(password: str) -> str:
    if not 15 <= len(password) <= 128:
        raise ValueError("Password must contain 15 to 128 characters")
    return PASSWORD_HASHER.hash(password)


def verify_password(password: str, encoded: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(encoded, password)
    except (VerificationError, InvalidHashError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def random_token() -> str:
    return secrets.token_urlsafe(32)


def session_csrf(settings: Settings, session_id: UUID) -> str:
    """Reproducible synchronizer token enables reload without rotating other tabs."""
    return hmac.new(
        settings.jwt_secret.get_secret_value().encode(),
        f"aegis:csrf:v1:{session_id}".encode(),
        hashlib.sha256,
    ).hexdigest()


@dataclass(frozen=True)
class AccessIdentity:
    user_id: UUID
    session_id: UUID


def access_token(settings: Settings, user_id: UUID, session_id: UUID) -> str:
    now = utcnow()
    return jwt.encode(
        {
            "sub": str(user_id),
            "sid": str(session_id),
            "jti": str(uuid4()),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "type": "access",
            "iat": now,
            "exp": now + timedelta(seconds=settings.access_token_seconds),
        },
        settings.jwt_secret.get_secret_value(),
        algorithm="HS256",
    )


def decode_access(settings: Settings, token: str) -> AccessIdentity:
    if len(token) > 4096:
        raise unauthorized()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["sub", "sid", "jti", "iss", "aud", "iat", "exp", "type"]},
        )
        if payload["type"] != "access":
            raise unauthorized()
        if any(not isinstance(payload[key], str) for key in ("sub", "sid", "jti")):
            raise unauthorized()
        UUID(payload["jti"])
        return AccessIdentity(UUID(payload["sub"]), UUID(payload["sid"]))
    except (jwt.InvalidTokenError, ValueError, TypeError, KeyError):
        raise unauthorized() from None
