"""Isolated real Redis queue and in-process Celery worker using the production factory."""

from typing import Any
from uuid import UUID, uuid4

import pytest
from celery import Celery
from celery.contrib.testing.worker import start_worker
from sqlalchemy.engine import make_url

from app.core.security import random_token
from app.modules.ingestion.processing import dispatch_once

from .conftest import Services
from .helper_ingestion import accept, due, enroll, envelope, processing_database, status
from .helpers import Case, Login

pytestmark = pytest.mark.integration


def test_real_celery_stages_durable_jobs_after_broker_failure_and_worker_restart(
    case: Case, admin: Login, services: Services
) -> None:
    from app.worker import create_celery

    source = enroll(admin)
    first = accept(admin.client, source, envelope("before-worker"))
    event_id = UUID(status(admin.client, source, first)["records"][0]["event_id"])
    database = processing_database(case)
    queue = f"aegis_test_{uuid4().hex}"
    settings = case.database.settings.model_copy(
        update={"redis_url": services.broker_url, "ingest_queue": queue}
    )
    bad_url = (
        make_url(services.broker_url.get_secret_value())
        .set(password=random_token())
        .render_as_string(hide_password=False)
    )
    results: list[Any] = []
    # A real authenticated Redis connection failure must retain the committed inbox.
    with Celery("aegis-test-unavailable", broker=bad_url) as unavailable:
        unavailable.conf.update(
            broker_connection_timeout=1,
            broker_transport_options={"socket_connect_timeout": 1, "socket_timeout": 1},
        )

        def broken_publish(identifier: str, generation: int) -> None:
            unavailable.send_task(
                "aegis.ingestion.stage", args=[identifier, generation], queue=queue, retry=False
            )

        assert dispatch_once(database, settings, broken_publish).failed == 1
    assert status(admin.client, source, first)["records"][0]["state"] == "pending"
    due(case, event_id)
    app = create_celery(settings)
    case.stack.callback(app.close)

    def publish(identifier: str, generation: int) -> None:
        results.append(
            app.send_task(
                "aegis.ingestion.stage", args=[identifier, generation], queue=queue, retry=False
            )
        )

    try:
        # Publish before any worker exists, then deliver the same persisted event twice.
        assert dispatch_once(database, settings, publish).published == 1
        publish(str(event_id), 1)
        with start_worker(
            app, pool="solo", queues=[queue], perform_ping_check=False, shutdown_timeout=15
        ):
            assert [result.get(timeout=20, disable_sync_subtasks=False) for result in results] == [
                "staged",
                "duplicate",
            ]
        assert status(admin.client, source, first)["records"][0]["attempts"] == 1
        second = accept(admin.client, source, envelope("during-worker-stop"))
        assert dispatch_once(database, settings, publish).published == 1
        assert status(admin.client, source, second)["records"][0]["state"] == "pending"
        # Delete only the one message in this random test queue to emulate queue loss.
        with app.connection_for_write() as connection:
            with connection.channel() as channel:
                assert channel.queue_purge(queue) == 1
        second_id = UUID(status(admin.client, source, second)["records"][0]["event_id"])
        due(case, second_id)
        assert dispatch_once(database, settings, publish).published == 1
        with start_worker(
            app, pool="solo", queues=[queue], perform_ping_check=False, shutdown_timeout=15
        ):
            assert results[-1].get(timeout=20, disable_sync_subtasks=False) == "staged"
        assert status(admin.client, source, second)["records"][0]["state"] == "staged"
    finally:
        for result in results:
            result.forget()
        with app.connection_for_write() as connection:
            with connection.channel() as channel:
                channel.queue_delete(queue)
