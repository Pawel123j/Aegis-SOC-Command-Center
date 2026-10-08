"""Recover ready local playbook steps independently of Redis and ClickHouse."""

import logging
import signal
from threading import Event
from types import FrameType

from app.core.config import get_settings
from app.core.observability import configure_logging
from app.infrastructure.database import Database
from app.modules.soar.processing import process_once

logger = logging.getLogger(__name__)


def main() -> int:
    configure_logging()
    stopping = Event()

    def stop(signum: int, frame: FrameType | None) -> None:
        stopping.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    database = Database(get_settings())
    try:
        while not stopping.is_set():
            try:
                process_once(database)
            except Exception:
                logger.error("application_error", extra={"event": "application_error"})
            stopping.wait(1)
    finally:
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
