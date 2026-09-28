"""Deterministic real-database regression for the refresh/admin lock ordering."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from typing import Any

import pytest
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from app.api import auth
from app.modules.audit.models import AuditLog
from app.modules.auth.models import AuthSession
from app.modules.users.models import User

from .helpers import Case, Login

pytestmark = pytest.mark.integration


def test_refresh_and_admin_patch_complete_without_deadlock_and_revoke_new_token(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = case.create_user(admin)
    principal = case.login(str(user["username"]), str(user["password"]))
    refresh_has_session_lock = Event()
    patch_has_user_lock = Event()
    release_refresh = Event()
    append_real_audit = auth.append_audit

    def pause_before_refresh_audit(session: Session, **kwargs: Any) -> AuditLog:
        if kwargs.get("action") == "auth.refresh":
            # The real refresh route has locked its AuthSession but has not inserted
            # its audit yet. That INSERT needs PostgreSQL KEY SHARE on the actor User.
            refresh_has_session_lock.set()
            assert release_refresh.wait(timeout=10), "Refresh barrier was not released"
        return append_real_audit(session, **kwargs)

    def observe_patch_revocation(
        connection: Any,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        if statement.lstrip().lower().startswith("update auth_sessions "):
            # The actual PATCH has already acquired its User lock, and is about to
            # wait for the AuthSession held by refresh. No mock returns DB results.
            patch_has_user_lock.set()

    monkeypatch.setattr(auth, "append_audit", pause_before_refresh_audit)
    patch_engine = admin.client.app.state.database.engine
    event.listen(patch_engine, "before_cursor_execute", observe_patch_revocation)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            refresh_future = executor.submit(
                principal.client.post,
                "/api/v1/auth/refresh",
                headers=principal.mutation_headers,
            )
            try:
                assert refresh_has_session_lock.wait(timeout=10), "Refresh did not lock its session"
                patch_future = executor.submit(
                    admin.client.patch,
                    f"/api/v1/users/{user['id']}",
                    json={"role": "read_only", "enabled": False},
                    headers={**admin.authorization, "If-Match": '"1"'},
                )
                assert patch_has_user_lock.wait(timeout=10), (
                    "PATCH did not reach session revocation"
                )
                # FOR UPDATE on User creates a lock cycle here. FOR NO KEY UPDATE
                # permits the audit's KEY SHARE, so refresh can commit and unblock PATCH.
                release_refresh.set()
                refreshed = refresh_future.result(timeout=10)
                patched = patch_future.result(timeout=10)
            finally:
                # A failed assertion must not strand the worker at the synchronization gate.
                release_refresh.set()
    finally:
        event.remove(patch_engine, "before_cursor_execute", observe_patch_revocation)

    assert refreshed.status_code == 200
    assert patched.status_code == 200
    assert patched.json()["version"] == 2
    for access in (principal.access, refreshed.json()["access_token"]):
        response = principal.client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}
        )
        assert response.status_code == 401
    assert (
        principal.client.post(
            "/api/v1/auth/refresh", headers=principal.mutation_headers
        ).status_code
        == 401
    )
    with Session(case.database.runtime) as session:
        stored_user = session.scalar(select(User).where(User.username == user["username"]))
        assert stored_user is not None
        assert stored_user.role.value == "read_only" and stored_user.enabled is False
        family = session.scalar(select(AuthSession).where(AuthSession.user_id == stored_user.id))
        assert family is not None and family.revoked_at is not None
