"""Phase 2 API helpers. Every source belongs to the test's disposable database."""

from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.infrastructure.database import Database, utcnow
from app.modules.ingestion.models import (
    BatchEvent,
    IngestCapacity,
    IngestionBatch,
    OutboxJob,
    RawEvent,
)

from .helpers import Case, Login


@dataclass(repr=False)
class Source:
    id: str
    token: str
    credential_id: str

    @property
    def authorization(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


def enroll(admin: Login, *, source_types: list[str] | None = None) -> Source:
    response = admin.client.post(
        "/api/v1/sources",
        json={
            "name": f"integration_{uuid4().hex}",
            "source_types": source_types or ["generic_json"],
            "timezone": "UTC",
        },
        headers=admin.authorization,
    )
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    credential = body["credential"]
    assert credential["token"].startswith("aegis_ingest_")
    assert set(credential["scopes"]) == {"events:write", "events:status"}
    return Source(body["source"]["id"], credential["token"], credential["id"])


def envelope(event_id: str | None = None, *, raw: Any = None) -> dict[str, Any]:
    result = {
        "source_type": "generic_json",
        "raw_event": {"message": "safe"} if raw is None else raw,
    }
    if event_id is not None:
        result["source_event_id"] = event_id
    return result


def submit(client: TestClient, source: Source, payload: Any, key: str | None = None) -> Any:
    return client.post(
        "/api/v1/events",
        json=payload,
        headers={**source.authorization, "Idempotency-Key": key or uuid4().hex},
    )


def accept(
    client: TestClient, source: Source, payload: Any, key: str | None = None
) -> dict[str, Any]:
    response = submit(client, source, payload, key)
    assert response.status_code == 202
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def status(client: TestClient, source: Source, batch: dict[str, Any]) -> dict[str, Any]:
    response = client.get(batch["status_url"], headers=source.authorization)
    assert response.status_code == 200
    assert "raw_event" not in response.text and source.token not in response.text
    return response.json()


def stored_counts(case: Case) -> dict[str, int]:
    with Session(case.database.runtime) as session:
        counts = {
            model.__name__: int(session.scalar(select(func.count()).select_from(model)) or 0)
            for model in (IngestionBatch, RawEvent, BatchEvent, OutboxJob)
        }
        capacity = session.get(IngestCapacity, 1)
        assert capacity is not None
        counts["capacity_events"] = capacity.event_count
        counts["capacity_bytes"] = capacity.byte_count
        counts["capacity_receipts"] = capacity.receipt_count
        return counts


def processing_database(case: Case) -> Database:
    database = Database(case.database.settings)
    case.stack.callback(database.close)
    return database


def due(case: Case, event_id: UUID, *, worker: bool = False) -> None:
    """Move only this test's persisted lease into the past; never replace the DB clock."""
    with Session(case.database.owner) as session:
        job = session.get(OutboxJob, event_id)
        assert job is not None
        job.available_at = utcnow() - timedelta(seconds=10)
        job.dispatch_until = utcnow() - timedelta(seconds=10)
        if worker:
            job.worker_until = utcnow() - timedelta(seconds=10)
        session.commit()
