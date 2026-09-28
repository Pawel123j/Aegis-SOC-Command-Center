"""Authentication acceptance tests against actual PostgreSQL and Redis."""

from datetime import timedelta

import jwt
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import random_token, token_hash, utcnow
from app.modules.audit.models import AuditLog
from app.modules.auth.models import AuthSession, PreAuthSession, RefreshToken

from .helpers import Case, Login

pytestmark = pytest.mark.integration


def test_login_persists_only_token_hashes_and_consumes_preauth(case: Case, admin: Login) -> None:
    client = case.client()
    csrf_response = client.get("/api/v1/auth/csrf")
    csrf = csrf_response.json()["csrf_token"]
    settings = case.database.settings
    preauth = client.cookies[settings.preauth_cookie_name]
    headers = {"Origin": settings.public_origin, "X-CSRF-Token": csrf}
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "INITIAL_ADMIN", "password": admin.password},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "httponly" in response.headers["set-cookie"].lower()
    assert "samesite=strict" in response.headers["set-cookie"].lower()
    refresh = client.cookies[settings.refresh_cookie_name]
    with Session(case.database.runtime) as session:
        stored_preauth = session.get(PreAuthSession, token_hash(preauth))
        assert stored_preauth is not None and stored_preauth.used_at is not None
        assert stored_preauth.csrf_token_hash == token_hash(csrf)
        assert session.get(RefreshToken, token_hash(refresh)) is not None
        assert session.get(RefreshToken, refresh) is None
        audit = str([row.details for row in session.scalars(select(AuditLog))])
        assert all(secret not in audit for secret in (preauth, refresh, csrf, admin.password))
    assert client.get("/api/v1/auth/csrf").json()["csrf_token"] == response.json()["csrf_token"]
    replay = client.post(
        "/api/v1/auth/login",
        json={"username": "initial_admin", "password": admin.password},
        headers={**headers, "Cookie": f"{settings.preauth_cookie_name}={preauth}"},
    )
    assert replay.status_code == 403


def test_bad_credentials_are_generic_and_audited(case: Case, admin: Login) -> None:
    results = []
    for username in ("initial_admin", "does_not_exist"):
        client = case.client()
        csrf = client.get("/api/v1/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": random_token()},
            headers={"Origin": case.database.settings.public_origin, "X-CSRF-Token": csrf},
        )
        assert response.status_code == 401
        results.append((response.json()["code"], response.json()["message"]))
    assert results[0] == results[1]
    with Session(case.database.runtime) as session:
        denied = list(
            session.scalars(
                select(AuditLog).where(
                    AuditLog.action == "auth.login", AuditLog.outcome == "denied"
                )
            )
        )
        assert len(denied) == 2
        assert all(set(row.details) == {"account_hash"} for row in denied)


def test_origin_and_csrf_fail_closed_without_consuming_login(case: Case, admin: Login) -> None:
    client = case.client()
    csrf = client.get("/api/v1/auth/csrf").json()["csrf_token"]
    good = {"Origin": case.database.settings.public_origin, "X-CSRF-Token": csrf}
    for headers in (
        {"X-CSRF-Token": csrf},
        {**good, "Origin": "https://attacker.invalid"},
        {"Origin": good["Origin"]},
        {**good, "X-CSRF-Token": random_token()},
    ):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "initial_admin", "password": admin.password},
            headers=headers,
        )
        assert response.status_code == 403
        assert response.json()["code"] == "csrf_failed"
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "initial_admin", "password": admin.password},
        headers=good,
    )
    assert response.status_code == 200
    for route in ("refresh", "logout"):
        response = admin.client.post(
            f"/api/v1/auth/{route}",
            headers={**admin.mutation_headers, "X-CSRF-Token": random_token()},
        )
        assert response.status_code == 403
    assert admin.client.get("/api/v1/auth/me", headers=admin.authorization).status_code == 200


def test_refresh_rotation_and_spent_token_replay_revoke_entire_family(
    case: Case, admin: Login
) -> None:
    cookie = case.database.settings.refresh_cookie_name
    old_refresh = admin.client.cookies[cookie]
    rotated = admin.client.post("/api/v1/auth/refresh", headers=admin.mutation_headers)
    assert rotated.status_code == 200
    current_refresh = admin.client.cookies[cookie]
    assert current_refresh != old_refresh
    new_access = rotated.json()["access_token"]
    with Session(case.database.runtime) as session:
        spent = session.get(RefreshToken, token_hash(old_refresh))
        current = session.get(RefreshToken, token_hash(current_refresh))
        assert spent is not None and spent.used_at is not None
        assert current is not None and current.used_at is None
        assert spent.session_id == current.session_id
    replay = admin.client.post(
        "/api/v1/auth/refresh",
        headers={**admin.mutation_headers, "Cookie": f"{cookie}={old_refresh}"},
    )
    assert replay.status_code == 401
    for access in (admin.access, new_access):
        assert (
            admin.client.get(
                "/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}
            ).status_code
            == 401
        )
    assert (
        admin.client.post("/api/v1/auth/refresh", headers=admin.mutation_headers).status_code == 401
    )
    with Session(case.database.runtime) as session:
        assert session.scalar(select(AuthSession.revoked_at)) is not None
        assert (
            session.scalar(select(AuditLog.id).where(AuditLog.action == "auth.refresh_reuse"))
            is not None
        )


def test_logout_revokes_access_and_refresh_immediately(case: Case, admin: Login) -> None:
    cookie = case.database.settings.refresh_cookie_name
    refresh = admin.client.cookies[cookie]
    response = admin.client.post("/api/v1/auth/logout", headers=admin.mutation_headers)
    assert response.status_code == 204 and response.content == b""
    assert cookie not in admin.client.cookies
    assert admin.client.get("/api/v1/auth/me", headers=admin.authorization).status_code == 401
    assert (
        admin.client.post(
            "/api/v1/auth/refresh",
            headers={**admin.mutation_headers, "Cookie": f"{cookie}={refresh}"},
        ).status_code
        == 401
    )


def test_invalid_jwt_claims_and_missing_authentication_are_rejected(
    case: Case, admin: Login
) -> None:
    settings = case.database.settings
    claims = jwt.decode(
        admin.access,
        settings.jwt_secret.get_secret_value(),
        algorithms=["HS256"],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )
    tokens = ["not-a-jwt"]
    for changed in (
        {"aud": "untrusted-audience"},
        {"iss": "untrusted-issuer"},
        {"exp": int((utcnow() - timedelta(minutes=5)).timestamp())},
    ):
        tokens.append(jwt.encode({**claims, **changed}, settings.jwt_secret.get_secret_value()))
    for token in tokens:
        response = admin.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401
        assert token not in response.text
    assert admin.client.get("/api/v1/auth/me").status_code == 401


def test_real_redis_limits_login_attempts_and_sets_retry_after(case: Case, admin: Login) -> None:
    client = case.client()
    for attempt in range(6):
        csrf = client.get("/api/v1/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "initial_admin", "password": random_token()},
            headers={"Origin": case.database.settings.public_origin, "X-CSRF-Token": csrf},
        )
        if attempt < 5:
            assert response.status_code == 401
        else:
            assert response.status_code == 429
            assert 1 <= int(response.headers["retry-after"]) <= 60
