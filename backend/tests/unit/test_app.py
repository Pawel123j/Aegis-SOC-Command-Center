"""Application schemas are prepared before concurrent HTTP requests arrive."""

import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from threading import Barrier, Lock
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import TypeAdapter

from app.main import create_app


def test_concurrent_application_builds_serialize_schema_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = TypeAdapter.__init__
    schema_build = Lock()
    starting = Barrier(2)
    filters_before = list(warnings.filters)

    def guarded_adapter(self: TypeAdapter[Any], *args: Any, **kwargs: Any) -> None:
        # Python 3.12 warning contexts are process-global. Widen the construction
        # window to deterministically expose overlapping framework schema work.
        assert schema_build.acquire(blocking=False), "Concurrent schema construction"
        try:
            time.sleep(0.005)
            original(self, *args, **kwargs)
        finally:
            schema_build.release()

    monkeypatch.setattr(TypeAdapter, "__init__", guarded_adapter)

    def build() -> object:
        starting.wait(timeout=5)
        return create_app()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(build) for _ in range(2)]
        # The deliberate delay applies to every adapter in the expanding API.
        # Keep a bounded deadlock guard without treating schema count as a speed test.
        applications = [future.result(timeout=45) for future in futures]
    assert applications[0] is not applications[1]
    assert warnings.filters == filters_before


def test_first_concurrent_requests_require_no_new_schema_adapters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    applications = [create_app(), create_app()]
    starting = Barrier(2)
    filters_before = list(warnings.filters)

    def unexpected_adapter(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Request handling attempted schema construction")

    # Existing adapters still validate normally. Any lazy route initialization
    # would attempt to create a new adapter and turn the first request into 500.
    monkeypatch.setattr(TypeAdapter, "__init__", unexpected_adapter)
    with ExitStack() as stack:
        clients = [TestClient(application) for application in applications]
        for client in clients:
            stack.callback(client.close)

        def request(client: TestClient) -> object:
            starting.wait(timeout=5)
            response = client.get("/health")
            assert response.status_code == 200
            assert response.json() == {"status": "ok"}
            return response

        # No lifespan is needed: /health must not connect to infrastructure.
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(request, client) for client in clients]
            for future in futures:
                future.result(timeout=10)
    assert warnings.filters == filters_before
