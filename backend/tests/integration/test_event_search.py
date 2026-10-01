"""Actual ClickHouse projection/search, replay dedupe and owner/runtime isolation."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session

from app.clickhouse_migrate import MIGRATIONS, migrate
from app.infrastructure.database import utcnow
from app.modules.events.clickhouse import (
    ClickHouseEvents,
    ClickHouseUnavailable,
    execute,
    json_rows,
)
from app.modules.events.schemas import SearchRequest
from app.modules.events.service import search
from app.modules.ingestion.processing import process_event
from app.modules.normalization.models import NormalizedEvent, PipelineJob
from app.modules.normalization.processing import process_once
from app.modules.normalization.schemas import NormalizedSecurityEvent

from .helper_ingestion import accept, enroll, envelope, processing_database, status
from .helpers import Case, Login

pytestmark = pytest.mark.integration
START = datetime(2026, 10, 1, tzinfo=UTC)
END = START + timedelta(days=1)


@pytest.fixture
def archive(case: Case) -> Iterator[ClickHouseEvents]:
    name = f"aegis_events_test_{uuid4().hex}"
    settings = case.database.settings
    if settings.clickhouse_admin_user is None or settings.clickhouse_admin_password is None:
        pytest.fail(
            "Event integration tests require ClickHouse migration credentials", pytrace=False
        )
    migrate(settings, name)
    try:
        yield ClickHouseEvents(settings, name)
    finally:
        assert name.startswith("aegis_events_test_") and len(name) == 50
        execute(
            settings,
            f"REVOKE SELECT, INSERT ON {name}.events FROM {settings.clickhouse_user}",
            owner=True,
            bounded=False,
        )
        execute(settings, f"DROP DATABASE {name} SYNC", owner=True, bounded=False)


def document(**updates: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "event_id": uuid4(),
        "source_id": uuid4(),
        "dataset_id": uuid4(),
        "run_id": UUID(int=0),
        "mode": "live",
        "timestamp": START + timedelta(hours=1),
        "received_at": START + timedelta(hours=2),
        "processed_at": START + timedelta(hours=2),
        "source": {"name": "source żółć", "type": "generic_json", "ip": "2001:db8::1", "port": 22},
        "user": {"name": "żółć"},
        "host": {"name": "server"},
        "event": {
            "category": "authentication",
            "type": "start",
            "action": "login",
            "outcome": "failure",
            "severity": "low",
        },
        "raw_event": {"message": "safe"},
        "raw_sha256": "0" * 64,
    }
    values.update(updates)
    return NormalizedSecurityEvent.model_validate(values).model_dump(mode="json")


def request(**values: Any) -> SearchRequest:
    return SearchRequest.model_validate({"from": START, "to": END, **values})


def test_duplicate_projection_is_one_result_before_background_merge(
    archive: ClickHouseEvents,
) -> None:
    event = document()
    archive.insert(event)
    archive.insert(event)
    archive.insert(event)
    items, total = archive.search(request(), START, END)
    assert total == 1 and items == [event]
    assert archive.get_event(UUID(event["event_id"])) == event
    assert archive.get_event(uuid4()) is None


def test_typed_search_scopes_and_half_open_time_window(archive: ClickHouseEvents) -> None:
    event = document()
    archive.insert(event)
    archive.insert(document(timestamp=END))
    archive.insert(document(mode="replay", run_id=uuid4()))
    filtered = request(
        q='source.ip = "2001:db8::01" AND username = "żółć" '
        'AND result = "failed" AND source.port >= 22',
        mode="live",
        source_id=event["source_id"],
        dataset_id=event["dataset_id"],
        run_id=event["run_id"],
    )
    assert archive.search(filtered, START, END) == ([event], 1)
    attack = document(user={"name": "'; DROP TABLE events; --"})
    archive.insert(attack)
    query = request(q='username = "\'; DROP TABLE events; --"')
    assert archive.search(query, START, END) == ([attack], 1)
    assert archive.search(request(q="user.name = null"), START, END) == ([], 0)


def test_cursor_pagination_has_no_duplicates_with_equal_timestamps(
    archive: ClickHouseEvents,
) -> None:
    user = uuid4()
    events = [document() for _ in range(5)]
    for event in events:
        archive.insert(event)
        archive.insert(event)
    data = request(limit=2)
    seen: list[str] = []
    for index in range(3):
        result = search(archive.settings, data, user, archive)
        assert result.total == 5
        seen.extend(str(event.event_id) for event in result.items)
        if index < 2:
            assert result.next_cursor is not None
            data = SearchRequest(limit=2, cursor=result.next_cursor)
        else:
            assert result.next_cursor is None
    expected = [
        event["event_id"]
        for event in sorted(events, key=lambda item: UUID(item["event_id"]).int, reverse=True)
    ]
    assert seen == expected and len(set(seen)) == 5


def test_mapped_ipv6_search_matches_equivalent_input_forms(archive: ClickHouseEvents) -> None:
    event = document(source={"name": "mapped", "type": "generic_json", "ip": "::ffff:192.0.2.5"})
    archive.insert(event)
    for value in ["::ffff:192.0.2.5", "::ffff:c000:205", "0:0:0:0:0:ffff:c000:0205"]:
        assert archive.search(request(q=f'source.ip = "{value}"'), START, END) == ([event], 1)


def test_actor_and_target_account_are_distinct_search_fields(archive: ClickHouseEvents) -> None:
    event = document(
        user={
            "id": "actor-id",
            "name": "actor",
            "realm": "actor-realm",
            "target": {"id": "target-id", "name": "target", "realm": "target-realm"},
        }
    )
    archive.insert(event)
    data = request(
        q='user.target.id = "target-id" AND user.target.name = "target" '
        'AND user.target.realm = "target-realm" AND username = "actor"'
    )
    assert archive.search(data, START, END) == ([event], 1)
    assert archive.search(request(q='username = "target"'), START, END) == ([], 0)


def test_string_parameters_preserve_backslashes_tabs_and_newlines(
    archive: ClickHouseEvents,
) -> None:
    for name in [r"domain\user", r"\N", "żółć\ttab\nnewline\rreturn"]:
        event = document(user={"name": name})
        archive.insert(event)
        data = request(q="username = " + json.dumps(name))
        assert archive.search(data, START, END) == ([event], 1)


def test_search_api_auth_validation_and_redacted_outage(
    case: Case, admin: Login, archive: ClickHouseEvents
) -> None:
    settings = case.database.settings.model_copy(update={"clickhouse_database": archive.database})
    client = case.client(settings)
    event = document()
    archive.insert(event)
    body = {"from": START.isoformat(), "to": END.isoformat()}
    assert client.post("/api/v1/events/search", json=body).status_code == 401
    source = enroll(admin)
    assert (
        client.post("/api/v1/events/search", json=body, headers=source.authorization).status_code
        == 401
    )
    result = client.post("/api/v1/events/search", json=body, headers=admin.authorization)
    assert result.status_code == 200 and result.json()["items"] == [event]
    assert result.headers["cache-control"] == "no-store"
    result = client.get(
        "/api/v1/events", params={**body, "limit": "100"}, headers=admin.authorization
    )
    assert result.status_code == 200 and result.json()["total"] == 1
    assert (
        client.get(f"/api/v1/events/{event['event_id']}", headers=admin.authorization).json()
        == event
    )
    assert client.get(f"/api/v1/events/{uuid4()}", headers=admin.authorization).status_code == 404
    assert (
        client.post(
            "/api/v1/events/search",
            json={**body, "q": 'user.name = "a"; DROP TABLE events'},
            headers=admin.authorization,
        ).status_code
        == 422
    )
    assert (
        client.get(
            "/api/v1/events", params={**body, "extra": "x"}, headers=admin.authorization
        ).status_code
        == 422
    )
    readonly = case.create_user(admin, "read_only")
    reader = case.login(str(readonly["username"]), str(readonly["password"]))
    assert (
        client.post("/api/v1/events/search", json=body, headers=reader.authorization).status_code
        == 200
    )
    unavailable = case.client(settings.model_copy(update={"clickhouse_url": "http://127.0.0.1:9"}))
    outage = unavailable.post("/api/v1/events/search", json=body, headers=admin.authorization)
    assert outage.status_code == 503 and outage.json()["code"] == "archive_unavailable"
    assert (
        settings.clickhouse_password.get_secret_value() not in outage.text
        and "127.0.0.1" not in outage.text
    )


def test_raw_to_normalized_to_real_search(
    case: Case, admin: Login, archive: ClickHouseEvents
) -> None:
    source = enroll(admin)
    batch = accept(
        admin.client,
        source,
        envelope(
            "search-integration",
            raw={
                "timestamp": "2026-10-01T01:00:00Z",
                "username": "żółć",
                "action": "login",
                "result": "failed",
                "source_ip": "192.0.2.10",
            },
        ),
    )
    event_id = UUID(status(admin.client, source, batch)["records"][0]["event_id"])
    database = processing_database(case)
    assert process_event(database, archive.settings, event_id, 1) == "staged"
    counts = process_once(database, archive.settings, archive.insert)
    assert counts == {"normalized": 1, "projected": 1}
    items, total = archive.search(request(q='username = "żółć" AND result = "failed"'), START, END)
    assert total == 1 and items[0]["event_id"] == str(event_id)
    with Session(case.database.runtime) as session:
        normalized = session.get(NormalizedEvent, event_id)
        pipeline = session.get(PipelineJob, event_id)
        assert normalized is not None and normalized.document == items[0]
        assert pipeline is not None and pipeline.state == "projected"


def test_projection_ack_loss_retries_identical_snapshot_without_inflated_count(
    case: Case, admin: Login, archive: ClickHouseEvents
) -> None:
    source = enroll(admin)
    batch = accept(
        admin.client,
        source,
        envelope(raw={"timestamp": "2026-10-01T02:00:00Z", "username": "replay-safe"}),
    )
    event_id = UUID(status(admin.client, source, batch)["records"][0]["event_id"])
    database = processing_database(case)
    assert process_event(database, archive.settings, event_id, 1) == "staged"
    sent: list[dict[str, Any]] = []

    def lose_ack(event: dict[str, Any]) -> None:
        archive.insert(event)
        sent.append(event)
        raise RuntimeError("secret-raw-error-that-must-not-be-persisted")

    assert process_once(database, archive.settings, lose_ack) == {"normalized": 2}
    with Session(case.database.owner) as session:
        job = session.get(PipelineJob, event_id)
        assert (
            job is not None
            and job.state == "normalized"
            and job.last_error_code == "projection_unavailable"
        )
        job.available_at = utcnow() - timedelta(seconds=1)
        session.commit()
    assert process_once(database, archive.settings, archive.insert) == {"projected": 1}
    assert process_once(database, archive.settings, archive.insert) == {}
    items, total = archive.search(request(), START, END)
    assert total == 1 and items == sent


def test_runtime_cannot_ddl_mutate_or_read_migration_ledger(archive: ClickHouseEvents) -> None:
    for sql in [
        "CREATE TABLE forbidden (id UInt8) ENGINE=Memory",
        "DROP TABLE events",
        "ALTER TABLE events ADD COLUMN forbidden UInt8",
        "TRUNCATE TABLE events",
        "SELECT * FROM schema_migrations",
        "CREATE USER forbidden",
        "ALTER TABLE events DELETE WHERE 1",
    ]:
        with pytest.raises(ClickHouseUnavailable, match="^archive_unavailable$"):
            execute(archive.settings, sql, database=archive.database, bounded=False)


def test_migration_is_idempotent_and_checks_checksum(
    archive: ClickHouseEvents, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    migrate(archive.settings, archive.database)
    rows = json_rows(
        execute(
            archive.settings,
            "SELECT version FROM schema_migrations FINAL FORMAT JSONEachRow",
            database=archive.database,
            owner=True,
        )
    )
    assert sorted(rows, key=lambda row: row["version"]) == [
        {"version": "0001_events"},
        {"version": "0002_event_targets"},
    ]
    altered = tmp_path / "0001_events.sql"
    altered.write_bytes((MIGRATIONS / "0001_events.sql").read_bytes() + b"\n")
    monkeypatch.setattr("app.clickhouse_migrate.MIGRATIONS", tmp_path)
    with pytest.raises(RuntimeError, match="archive_migration_checksum_mismatch"):
        migrate(archive.settings, archive.database)
