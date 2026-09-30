"""Staging rejects unusable contents without exposing or changing raw data."""

import hashlib
import importlib
from collections.abc import Iterator
from dataclasses import replace
from types import ModuleType
from typing import Any
from unittest.mock import Mock
from uuid import uuid4

import pytest

from app.core.config import Settings, get_settings
from app.modules.ingestion.processing import (
    EventSnapshot,
    PermanentProcessingError,
    retry_delay,
    validate_raw_event,
)
from app.modules.ingestion.schemas import canonical_json


def snapshot(raw: object, source_type: str = "generic_json") -> EventSnapshot:
    envelope = {"source_type": source_type, "raw_event": raw}
    encoded = canonical_json(envelope)
    return EventSnapshot(
        uuid4(), envelope, hashlib.sha256(encoded).hexdigest(), len(encoded), source_type
    )


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    values = {
        "database_url": "postgresql+psycopg://aegis_app:unit-db-key@localhost:5432/aegis",
        "redis_url": "redis://:unit-redis-key@localhost:6379/0",
        "clickhouse_url": "http://localhost:8123",
        "clickhouse_user": "aegis",
        "clickhouse_password": "unit-clickhouse-key",
        "jwt_secret": "test-only-jwt-signing-material-with-32-bytes",
        "public_origin": "https://aegis.example.test",
        "local_http": "false",
    }
    for key, value in values.items():
        monkeypatch.setenv(f"AEGIS_{key.upper()}", value)
    return Settings.model_validate(values)


@pytest.mark.parametrize("raw", [{}, {"user": "ąę", "number": 1.5}, '{"message":"ok"}'])
def test_supported_json_contents_are_staged_without_mutation(raw: object) -> None:
    event = snapshot(raw)
    before = canonical_json(event.envelope)
    validate_raw_event(event)
    assert canonical_json(event.envelope) == before


@pytest.mark.parametrize(
    "source_type", ["linux_auth", "windows_auth", "windows_process", "firewall", "nginx"]
)
def test_other_source_formats_remain_raw_for_future_normalization(source_type: str) -> None:
    validate_raw_event(snapshot("unparsed log record", source_type))


@pytest.mark.parametrize("raw", ["", " ", "\n\t", "\u2003"])
def test_empty_raw_text_has_stable_code(raw: str) -> None:
    with pytest.raises(PermanentProcessingError, match="^empty_payload$"):
        validate_raw_event(snapshot(raw))


@pytest.mark.parametrize(
    "raw",
    [
        "not-json-private-data",
        "[]",
        "null",
        "false",
        "1",
        '{"n":NaN}',
        '{"n":1e400}',
        '{"n":Infinity}',
        '{"user":"first","user":"second"}',
        '{"nested":{"user":"first","user":"second"}}',
        '{"user":"first","\\u0075ser":"second"}',
    ],
)
def test_invalid_json_has_redacted_stable_code(raw: str) -> None:
    with pytest.raises(PermanentProcessingError, match="^invalid_json$") as caught:
        validate_raw_event(snapshot(raw))
    assert caught.value.code == "invalid_json"
    assert "private" not in str(caught.value)


def test_deep_json_text_is_rejected_after_parse() -> None:
    raw = '{"a":' * 30 + "0" + "}" * 30
    with pytest.raises(PermanentProcessingError, match="^invalid_json$"):
        validate_raw_event(snapshot(raw))


@pytest.mark.parametrize("mutation", ["hash", "size", "contents", "source_type"])
def test_integrity_mismatch_is_quarantined(mutation: str) -> None:
    event = snapshot({"message": "original"})
    if mutation == "hash":
        event = replace(event, payload_hash="0" * 64)
    elif mutation == "size":
        event = replace(event, payload_bytes=event.payload_bytes + 1)
    elif mutation == "contents":
        event = replace(
            event, envelope={"source_type": "generic_json", "raw_event": {"edited": True}}
        )
    else:
        event = replace(event, source_type="linux_auth")
    with pytest.raises(PermanentProcessingError, match="^integrity_mismatch$"):
        validate_raw_event(event)


def test_invalid_envelope_and_nonfinite_values_are_permanent() -> None:
    with pytest.raises(PermanentProcessingError, match="^invalid_payload$"):
        validate_raw_event(snapshot("data", "unknown_source"))
    event = replace(snapshot({}), envelope={"raw_event": {"bad": float("nan")}})
    with pytest.raises(PermanentProcessingError, match="^invalid_payload$"):
        validate_raw_event(event)


def test_snapshot_repr_and_unknown_error_codes_never_render_payload() -> None:
    event = snapshot({"private": "very-sensitive"})
    assert "very-sensitive" not in repr(event)
    error = PermanentProcessingError("database-password-private-message")
    assert error.code == "invalid_payload"
    assert str(error) == "invalid_payload"


def test_backoff_is_exponential_and_bounded(settings: Settings) -> None:
    assert [retry_delay(settings, i) for i in range(1, 8)] == [2, 4, 8, 16, 32, 60, 60]
    assert retry_delay(settings, 10**9) == 60
    assert retry_delay(settings, -(10**9)) == 2


@pytest.fixture
def worker(settings: Settings) -> Iterator[ModuleType]:
    get_settings.cache_clear()
    module = importlib.import_module("app.worker")
    yield module
    get_settings.cache_clear()


def test_worker_factory_defers_database_and_owns_its_settings(
    settings: Settings, worker: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = Mock()
    constructor = Mock(return_value=database)
    process = Mock(return_value="staged")
    monkeypatch.setattr(worker, "Database", constructor)
    monkeypatch.setattr(worker, "process_event", process)
    first_settings = settings.model_copy(update={"ingest_queue": "unit.first"})
    second_settings = settings.model_copy(update={"ingest_queue": "unit.second"})
    first = worker.create_celery(first_settings)
    second = worker.create_celery(second_settings)
    try:
        constructor.assert_not_called()
        event_id = uuid4()
        assert first.tasks["aegis.ingestion.stage"].run(str(event_id), 2) == "staged"
        constructor.assert_called_once_with(first_settings)
        process.assert_called_once_with(database, first_settings, event_id, 2)
        database.close.assert_called_once()
        assert second.tasks["aegis.ingestion.stage"].run(str(event_id), 3) == "staged"
        assert constructor.call_args.args == (second_settings,)
        assert first.tasks["aegis.ping"].run() == "pong"
        assert first.conf.task_routes["aegis.ingestion.stage"]["queue"] == "unit.first"
        assert second.conf.task_routes["aegis.ingestion.stage"]["queue"] == "unit.second"
    finally:
        first.close()
        second.close()


@pytest.mark.parametrize(
    "identity,generation",
    [("bad-id", 1), (None, 1), (str(uuid4()), True), (str(uuid4()), 0), (str(uuid4()), "1")],
)
def test_worker_rejects_untrusted_messages_before_database(
    settings: Settings,
    worker: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    identity: Any,
    generation: Any,
) -> None:
    constructor = Mock()
    monkeypatch.setattr(worker, "Database", constructor)
    application = worker.create_celery(settings)
    try:
        assert (
            application.tasks["aegis.ingestion.stage"].run(identity, generation)
            == "invalid_message"
        )
        constructor.assert_not_called()
    finally:
        application.close()


def test_worker_redacts_database_failure_and_closes_pool(
    settings: Settings, worker: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = Mock()
    monkeypatch.setattr(worker, "Database", Mock(return_value=database))
    monkeypatch.setattr(
        worker, "process_event", Mock(side_effect=RuntimeError("private-driver-URL"))
    )
    application = worker.create_celery(settings)
    try:
        assert application.tasks["aegis.ingestion.stage"].run(str(uuid4()), 1) == "unavailable"
        database.close.assert_called_once()
    finally:
        application.close()
