"""Celery transports event IDs; PostgreSQL owns processing state and recovery."""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from celery import Celery
from celery.signals import setup_logging

from app.core.config import Settings, get_settings
from app.core.observability import configure_logging
from app.infrastructure.database import Database
from app.modules.ingestion.processing import process_event

logger = logging.getLogger(__name__)


# Celery exposes these decorators without typing metadata.
@setup_logging.connect  # type: ignore[untyped-decorator]
def configure_worker_logging(**kwargs: Any) -> None:
    """Prevent Celery defaults from logging task arguments and connection URLs."""
    configure_logging()


def create_celery(settings: Settings) -> Celery:
    """Each app owns its settings and tasks; no SQL connection exists before fork."""
    application = Celery(
        "aegis",
        broker=settings.redis_url.get_secret_value(),
        backend=settings.redis_url.get_secret_value(),
    )
    application.conf.update(
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
        broker_transport_options={
            "visibility_timeout": 120,
            "socket_timeout": 2,
            "socket_connect_timeout": 2,
        },
        result_backend_transport_options={"visibility_timeout": 120},
        visibility_timeout=120,
        redis_socket_connect_timeout=2,
        redis_socket_timeout=2,
        enable_utc=True,
        timezone="UTC",
        task_routes={"aegis.ingestion.stage": {"queue": settings.ingest_queue}},
    )

    @application.task(  # type: ignore[untyped-decorator]
        name="aegis.ping", ignore_result=False, shared=False
    )
    def ping() -> str:
        return "pong"

    @application.task(  # type: ignore[untyped-decorator]
        name="aegis.ingestion.stage", ignore_result=False, shared=False
    )
    def stage(event_id: str, generation: int) -> str:
        try:
            if not isinstance(event_id, str) or len(event_id) > 36:
                return "invalid_message"
            if type(generation) is not int or generation < 1:
                return "invalid_message"
            identity = UUID(event_id)
        except (ValueError, TypeError):
            return "invalid_message"
        database: Database | None = None
        try:
            database = Database(settings)
            return process_event(database, settings, identity, generation)
        except Exception:
            # A failed DB completion stays recoverable after lease expiration.
            # Never send driver exception strings to the result backend or logs.
            logger.error("application_error", extra={"event": "application_error"})
            return "unavailable"
        finally:
            if database is not None:
                try:
                    database.close()
                except Exception:
                    logger.error("application_error", extra={"event": "application_error"})

    return application


celery_app = create_celery(get_settings())
