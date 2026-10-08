"""Public minimal health probes and internal bounded Prometheus metrics."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Request
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text
from starlette.responses import JSONResponse, Response

from app.core.observability import REGISTRY

router = APIRouter(tags=["health"])
logger = logging.getLogger(__name__)
EXPECTED_REVISION = "0012_soar"
DEPENDENCY_TIMEOUT_SECONDS = 2.0


def _unavailable(component: str) -> None:
    logger.warning(
        "dependency_check_failed",
        extra={"event": "dependency_check_failed", "component": component},
    )


def _postgresql_status(request: Request) -> dict[str, str]:
    checks = {"postgresql": "unavailable", "migrations": "unavailable"}
    try:
        with request.app.state.database.sessions() as session:
            session.execute(text("SET LOCAL statement_timeout = '2000ms'"))
            if session.execute(text("SELECT 1")).scalar_one() != 1:
                _unavailable("postgresql")
                return checks
            checks["postgresql"] = "ok"
            revision = session.execute(text("SELECT version_num FROM alembic_version"))
            if revision.scalar_one() == EXPECTED_REVISION:
                checks["migrations"] = "ok"
            else:
                _unavailable("migrations")
    except Exception:
        _unavailable("postgresql" if checks["postgresql"] != "ok" else "migrations")
    return checks


def _redis_status(request: Request) -> str:
    try:
        if request.app.state.redis.ping() is True:
            return "ok"
    except Exception:
        pass
    _unavailable("redis")
    return "unavailable"


def _clickhouse_status(request: Request) -> str:
    settings = request.app.state.settings
    try:
        base_url = settings.clickhouse_url.rstrip("/")
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            _unavailable("clickhouse")
            return "unavailable"
        with httpx.Client(
            auth=(settings.clickhouse_user, settings.clickhouse_password.get_secret_value()),
            timeout=DEPENDENCY_TIMEOUT_SECONDS,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            ping = client.get(f"{base_url}/ping")
            if ping.status_code != 200 or ping.text.strip() != "Ok.":
                _unavailable("clickhouse")
                return "unavailable"
            # /ping is a liveness handler; a query also validates configured auth.
            authenticated = client.post(
                f"{base_url}/", content="SELECT 1", headers={"Content-Type": "text/plain"}
            )
            if authenticated.status_code == 200 and authenticated.text.strip() == "1":
                return "ok"
    except Exception:
        pass
    _unavailable("clickhouse")
    return "unavailable"


def detailed_status(request: Request) -> dict[str, Any]:
    """Run probes for an authorized system-health endpoint, without secret detail."""
    checks = _postgresql_status(request)
    checks["redis"] = _redis_status(request)
    checks["clickhouse"] = _clickhouse_status(request)
    ready = all(value == "ok" for value in checks.values())
    return {"status": "ready" if ready else "not_ready", "checks": checks}


@router.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    """Liveness does not depend on infrastructure availability."""
    return {"status": "ok"}


@router.get("/ready", include_in_schema=False)
def ready(request: Request) -> JSONResponse:
    """Expose only aggregate readiness; component information requires permission."""
    status = detailed_status(request)["status"]
    return JSONResponse(
        {"status": status},
        status_code=200 if status == "ready" else 503,
        headers={"Cache-Control": "no-store"},
    )


@router.get("/metrics", include_in_schema=False)
def metrics() -> Response:
    """Internal endpoint: the deployment proxy must not publish this path."""
    return Response(
        content=generate_latest(REGISTRY),
        headers={"Content-Type": CONTENT_TYPE_LATEST, "Cache-Control": "no-store"},
    )
