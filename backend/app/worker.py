"""Celery transport foundation; no simulated security pipeline tasks."""

from __future__ import annotations

from typing import Any

from celery import Celery
from celery.signals import setup_logging

from app.core.config import get_settings
from app.core.observability import configure_logging

settings = get_settings()
celery_app = Celery(
    "aegis",
    broker=settings.redis_url.get_secret_value(),
    backend=settings.redis_url.get_secret_value(),
)
celery_app.conf.update(
    accept_content=["json"],
    task_serializer="json",
    result_serializer="json",
    result_accept_content=["json"],
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_soft_time_limit=20,
    task_time_limit=30,
    worker_prefetch_multiplier=1,
    worker_hijack_root_logger=False,
    worker_redirect_stdouts=False,
    task_send_sent_event=False,
    worker_send_task_events=False,
    task_remote_tracebacks=False,
    result_extended=False,
    result_expires=3600,
    broker_connection_retry_on_startup=True,
    broker_connection_timeout=2,
    broker_transport_options={"visibility_timeout": 120},
    result_backend_transport_options={"visibility_timeout": 120},
    visibility_timeout=120,
    redis_socket_connect_timeout=2,
    redis_socket_timeout=2,
    enable_utc=True,
    timezone="UTC",
)


# Celery exposes these decorators without typing metadata.
@setup_logging.connect  # type: ignore[untyped-decorator]
def configure_worker_logging(**kwargs: Any) -> None:
    """Prevent Celery defaults from logging task arguments and connection URLs."""
    configure_logging()


@celery_app.task(name="aegis.ping", ignore_result=False)  # type: ignore[untyped-decorator]
def ping() -> str:
    """A harmless broker/worker/result-backend smoke test."""
    return "pong"
