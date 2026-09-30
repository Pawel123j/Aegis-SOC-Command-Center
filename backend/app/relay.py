"""Run the durable outbox sweep as a separately supervised process."""

from __future__ import annotations

import logging
import signal
from threading import Event
from types import FrameType

from app.core.config import get_settings
from app.core.observability import configure_logging
from app.infrastructure.database import Database
from app.modules.ingestion.processing import dispatch_once

logger = logging.getLogger(__name__)


def main() -> int:
    configure_logging()
    stopping = Event()

    def stop(signum: int, frame: FrameType | None) -> None:
        stopping.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        from app.worker import create_celery

        settings = get_settings()
        publisher = create_celery(settings)
        database = Database(settings)
    except Exception:
        logger.error("application_error", extra={"event": "application_error"})
        return 1

    def publish(event_id: str, generation: int) -> None:
        publisher.send_task(
            "aegis.ingestion.stage",
            args=[event_id, generation],
            queue=settings.ingest_queue,
            retry=False,
            ignore_result=True,
        )

    logger.info("application_started", extra={"event": "application_started"})
    try:
        while not stopping.is_set():
            try:
                dispatch_once(database, settings, publish)
            except Exception:
                # Unfinished claims recover after their committed leases expire.
                logger.error("application_error", extra={"event": "application_error"})
            stopping.wait(settings.ingest_relay_poll_seconds)
    finally:
        database.close()
        publisher.close()
        logger.info("application_stopped", extra={"event": "application_stopped"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
