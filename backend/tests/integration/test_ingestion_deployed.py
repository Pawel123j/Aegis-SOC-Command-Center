"""Real Linux HTTP, relay and prefork worker processes on disposable storage."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import ExitStack
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.modules.ingestion.models import OutboxJob

from .conftest import Services
from .helper_ingestion import Source, enroll, envelope
from .helpers import BACKEND, Case, Login

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux process groups and prefork"),
]


def _child_environment(settings: Settings) -> dict[str, str]:
    # Remove inherited AEGIS_* values, including integration-only owner credentials.
    # Every application setting then comes from this test's disposable configuration.
    environment = {
        key: value for key, value in os.environ.items() if not key.upper().startswith("AEGIS_")
    }
    for name in Settings.model_fields:
        value = getattr(settings, name)
        if isinstance(value, SecretStr):
            value = value.get_secret_value()
        environment[f"AEGIS_{name.upper()}"] = str(value)
    environment["PYTHONPATH"] = str(BACKEND)
    environment["PYTHONUNBUFFERED"] = "1"
    return environment


def _stop(process: subprocess.Popen[bytes]) -> None:
    """Reap our child and remove any prefork descendants in its own session."""
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
    finally:
        # A prematurely exited leader can leave prefork children behind.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _start(
    stack: ExitStack,
    environment: dict[str, str],
    *arguments: str,
    pass_fds: tuple[int, ...] = (),
) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [sys.executable, "-m", *arguments],
        cwd=BACKEND,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        pass_fds=pass_fds,
    )
    stack.callback(_stop, process)
    return process


def _await(
    predicate: Callable[[], bool],
    processes: tuple[subprocess.Popen[bytes], ...],
    *,
    timeout: float,
    label: str,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        assert all(process.poll() is None for process in processes), f"{label}: child exited"
        if predicate():
            return
        time.sleep(0.1)
    pytest.fail(f"{label}: deadline exceeded", pytrace=False)


def _healthy(client: httpx.Client) -> bool:
    try:
        return client.get("/ready").status_code == 200
    except httpx.RequestError:
        return False


def _accept(client: httpx.Client, source: Source, identity: str) -> dict[str, Any]:
    response = client.post(
        "/api/v1/events",
        json=envelope(identity),
        headers={**source.authorization, "Idempotency-Key": uuid4().hex},
    )
    assert response.status_code == 202, "HTTP intake did not accept the synthetic event"
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def _record(client: httpx.Client, source: Source, receipt: dict[str, Any]) -> dict[str, Any]:
    response = client.get(receipt["status_url"], headers=source.authorization)
    assert response.status_code == 200, "HTTP receipt status unavailable"
    body = response.json()
    assert len(body["records"]) == 1, "Unexpected receipt record count"
    return body["records"][0]


def test_http_relay_prefork_stages_and_recovers_after_worker_stop(
    case: Case, admin: Login, services: Services
) -> None:
    """Stop and restart real workers without rewriting durable clocks or states."""
    from app.worker import create_celery

    queue = f"aegis_deployed_{uuid4().hex}"
    settings = case.database.settings.model_copy(
        update={
            "redis_url": services.broker_url,
            "ingest_queue": queue,
            "ingest_relay_poll_seconds": 0.1,
            "ingest_redelivery_seconds": 10,
            "ingest_max_dispatch_attempts": 100,
        }
    )
    environment = _child_environment(settings)
    source = enroll(admin)
    publisher = create_celery(settings)

    def remove_queue() -> None:
        # No source payloads or results are published; relay uses ignore_result=True.
        # Delete only this unguessable queue, never purge shared broker state.
        failed = False
        try:
            with publisher.connection_for_write() as connection:
                with connection.channel() as channel:
                    channel.queue_delete(queue)
        except Exception:
            failed = True
        finally:
            try:
                publisher.close()
            except Exception:
                failed = True
        if failed:
            pytest.fail("Isolated deployment queue cleanup failed", pytrace=False)

    with ExitStack() as stack:
        stack.callback(remove_queue)
        listener = stack.enter_context(socket.socket())
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        api = _start(
            stack,
            environment,
            "uvicorn",
            "app.main:app",
            "--fd",
            str(listener.fileno()),
            "--no-proxy-headers",
            "--no-access-log",
            "--log-level",
            "warning",
            pass_fds=(listener.fileno(),),
        )
        client = stack.enter_context(
            httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=2, trust_env=False)
        )
        _await(lambda: _healthy(client), (api,), timeout=20, label="HTTP readiness")
        relay = _start(stack, environment, "app.relay")

        def start_worker(worker_stack: ExitStack) -> subprocess.Popen[bytes]:
            return _start(
                worker_stack,
                environment,
                "celery",
                "-A",
                "app.worker:celery_app",
                "worker",
                "--loglevel=WARNING",
                "--pool=prefork",
                "--concurrency=2",
                f"--queues={queue}",
                f"--hostname={queue}@%h",
            )

        worker_stack = stack.enter_context(ExitStack())
        worker = start_worker(worker_stack)
        first = _accept(client, source, "running-worker")
        _await(
            lambda: _record(client, source, first)["state"] == "staged",
            (api, relay, worker),
            timeout=30,
            label="HTTP to relay to prefork worker",
        )
        assert _record(client, source, first)["attempts"] == 1

        worker_stack.close()
        stopped = _accept(client, source, "stopped-worker")
        event_id = UUID(_record(client, source, stopped)["event_id"])

        def published_while_stopped() -> bool:
            with Session(case.database.runtime) as session:
                job = session.get(OutboxJob, event_id)
                acknowledged = (
                    job is not None
                    and job.dispatch_attempts > 0
                    and job.dispatch_token is None
                    and job.last_error_code is None
                    and job.state == "pending"
                )
            if not acknowledged:
                return False
            try:
                with publisher.connection_for_write() as connection:
                    with connection.channel() as channel:
                        return channel.queue_declare(queue, passive=True).message_count > 0
            except Exception:
                pytest.fail("Isolated broker queue inspection failed", pytrace=False)

        _await(
            published_while_stopped,
            (api, relay),
            timeout=15,
            label="Relay publication while worker stopped",
        )
        assert _record(client, source, stopped)["attempts"] == 0
        resumed = start_worker(stack.enter_context(ExitStack()))
        _await(
            lambda: _record(client, source, stopped)["state"] == "staged",
            (api, relay, resumed),
            timeout=30,
            label="Prefork worker restart recovery",
        )
        record = _record(client, source, stopped)
        assert record["generation"] == 1 and record["attempts"] == 1
        assert record["error_code"] is None
