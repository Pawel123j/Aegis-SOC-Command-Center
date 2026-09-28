"""Bounded request telemetry and logging that never serializes arbitrary payloads."""

from __future__ import annotations

import json
import logging
import re
import sys
import time
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Histogram
from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
REQUEST_ID: ContextVar[str | None] = ContextVar("request_id", default=None)
REGISTRY = CollectorRegistry()
HTTP_REQUESTS = Counter(
    "aegis_http_requests_total",
    "Completed HTTP requests by bounded route template.",
    ("method", "route", "status"),
    registry=REGISTRY,
)
HTTP_DURATION = Histogram(
    "aegis_http_request_duration_seconds",
    "HTTP request duration including response transmission.",
    ("method", "route"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    registry=REGISTRY,
)
_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_EVENTS = frozenset(
    {
        "http_request",
        "http_error",
        "dependency_check_failed",
        "worker_ready",
        "application_started",
        "application_stopped",
        "application_error",
        "log_record",
    }
)
_COMPONENTS = frozenset({"postgresql", "migrations", "redis", "clickhouse"})
_LOGGER_GROUPS = frozenset({"app", "uvicorn", "celery", "kombu", "sqlalchemy", "httpx"})
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}
logger = logging.getLogger(__name__)


def safe_request_id(value: Any) -> str | None:
    """Accept only short ASCII correlation IDs; never preserve arbitrary headers."""
    if isinstance(value, str) and REQUEST_ID_PATTERN.fullmatch(value):
        return value
    return None


class SafeJSONFormatter(logging.Formatter):
    """Serialize an allowlist, excluding messages, args, headers and tracebacks.

    Dependency exception messages may embed URLs, credentials or SQL parameters.
    Dropping arbitrary strings is safer than trying to recognize every secret.
    """

    def format(self, record: logging.LogRecord) -> str:
        event = getattr(record, "event", "log_record")
        group = record.name.partition(".")[0]
        output: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": logging.getLevelName(record.levelno),
            "logger": group if group in _LOGGER_GROUPS else "external",
            "event": event if isinstance(event, str) and event in _EVENTS else "log_record",
        }
        request_id = safe_request_id(REQUEST_ID.get())
        if request_id:
            output["request_id"] = request_id
        component = getattr(record, "component", None)
        if isinstance(component, str) and component in _COMPONENTS:
            output["component"] = component
        method = getattr(record, "http_method", None)
        if isinstance(method, str) and (method in _METHODS or method == "OTHER"):
            output["method"] = method
        status = getattr(record, "http_status", None)
        if isinstance(status, int) and 100 <= status <= 599:
            output["status"] = status
        elapsed = getattr(record, "duration_ms", None)
        if isinstance(elapsed, int) and 0 <= elapsed <= 86_400_000:
            output["duration_ms"] = elapsed
        # Deliberately omit even route extras: a third-party caller may pass a URL.
        return json.dumps(output, separators=(",", ":"), ensure_ascii=True)


def configure_logging(level: int = logging.INFO) -> None:
    """Install the same redaction policy for API, worker and dependency loggers."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(SafeJSONFormatter())
    logging.basicConfig(level=level, handlers=[handler], force=True)
    for name in ("uvicorn", "uvicorn.error", "celery", "celery.task"):
        current = logging.getLogger(name)
        current.handlers.clear()
        current.propagate = True
    # Access logs include raw paths/query strings; middleware records safe metadata.
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


class ObservabilityMiddleware:
    """Pure ASGI middleware: safe IDs, security headers and bounded metrics."""

    def __init__(self, app: ASGIApp, *, local_http: bool = False) -> None:
        self.app = app
        self.local_http = local_http

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        candidates = [
            value.decode("latin-1")
            for name, value in scope.get("headers", [])
            if name.lower() == b"x-request-id"
        ]
        supplied = safe_request_id(candidates[0]) if len(candidates) == 1 else None
        request_id = supplied or uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        token = REQUEST_ID.set(request_id)
        started = time.perf_counter()
        status = 500
        response_started = False
        method = scope["method"] if scope["method"] in _METHODS else "OTHER"

        async def send_response(message: Message) -> None:
            nonlocal status, response_started
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request_id
                for name, value in _SECURITY_HEADERS.items():
                    headers[name] = value
                application = scope.get("app")
                settings = getattr(getattr(application, "state", None), "settings", None)
                local_http = getattr(settings, "local_http", self.local_http)
                if scope.get("scheme") == "https" and not local_http:
                    headers["Strict-Transport-Security"] = "max-age=31536000"
                elif "Strict-Transport-Security" in headers:
                    del headers["Strict-Transport-Security"]
                response_started = True
            await send(message)

        try:
            try:
                await self.app(scope, receive, send_response)
            except Exception:
                logger.error("http_error", extra={"event": "http_error"})
                if response_started:
                    raise
                response = JSONResponse(
                    {
                        "code": "internal_error",
                        "message": "Internal server error",
                        "request_id": request_id,
                    },
                    status_code=500,
                )
                await response(scope, receive, send_response)
        finally:
            duration = max(0.0, time.perf_counter() - started)
            route = getattr(scope.get("route"), "path", None)
            route_label = route if isinstance(route, str) else "unmatched"
            HTTP_REQUESTS.labels(method, route_label, str(status)).inc()
            HTTP_DURATION.labels(method, route_label).observe(duration)
            logger.info(
                "http_request",
                extra={
                    "event": "http_request",
                    "http_method": method,
                    "http_status": status,
                    "duration_ms": int(duration * 1000),
                },
            )
            REQUEST_ID.reset(token)
