"""All correlation fixtures enter through real authenticated raw ingestion."""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.modules.ingestion.models import IngestionSource
from app.modules.ingestion.processing import process_event
from app.modules.normalization.models import NormalizedEvent
from app.modules.normalization.processing import process_once as normalize_once

from .helper_ingestion import Source, accept, enroll, processing_database, status
from .helpers import Case, Login

RULE = "possible_bruteforce_compromise"


def auth_event(timestamp: datetime, outcome: str = "failure", **raw_values: Any) -> dict[str, Any]:
    raw = {
        "host": {"id": "registered-host", "name": "server"},
        "user": {"id": "user-1", "name": "alice", "realm": "LAB"},
        "source": {"ip": "192.0.2.1"},
        "event": {"category": "authentication", "outcome": outcome},
        **raw_values,
    }
    return {"source_type": "generic_json", "timestamp": timestamp.isoformat(), "raw_event": raw}


def auth_sequence(start: datetime) -> list[dict[str, Any]]:
    return [
        *[auth_event(start + timedelta(seconds=index)) for index in range(5)],
        auth_event(start + timedelta(seconds=5), "success"),
    ]


def normalize_inputs(
    case: Case,
    admin: Login,
    events: list[dict[str, Any]],
    *,
    source: Source | None = None,
    replay: tuple[UUID, UUID] | None = None,
) -> tuple[Source, list[UUID]]:
    source = source or enroll(
        admin, source_types=sorted({event["source_type"] for event in events})
    )
    if replay:
        with Session(case.database.owner) as db:
            db.execute(
                update(IngestionSource)
                .where(IngestionSource.id == source.id)
                .values(mode="replay", dataset_id=replay[0], run_id=replay[1])
            )
            db.commit()
    ids = []
    for offset in range(0, len(events), 500):
        receipt = accept(
            admin.client,
            source,
            {
                "events": [
                    dict(event, source_event_id=uuid4().hex)
                    for event in events[offset : offset + 500]
                ]
            },
        )
        ids.extend(
            UUID(record["event_id"]) for record in status(admin.client, source, receipt)["records"]
        )
    database = processing_database(case)
    for event_id in ids:
        assert process_event(database, case.database.settings, event_id, 1) == "staged"
    # Normalization and projection each consume a claim from the batch budget.
    # Observe actual durable progress instead of assuming one claim per input.
    for _ in range(2 * len(ids) // case.database.settings.pipeline_batch_size + 3):
        normalize_once(database, case.database.settings, lambda _: None)
        with Session(case.database.runtime) as db:
            completed = int(
                db.scalar(
                    select(func.count())
                    .select_from(NormalizedEvent)
                    .where(NormalizedEvent.event_id.in_(ids))
                )
                or 0
            )
        if completed == len(ids):
            break
    with Session(case.database.runtime) as db:
        assert len(
            list(
                db.scalars(
                    select(NormalizedEvent.event_id).where(NormalizedEvent.event_id.in_(ids))
                )
            )
        ) == len(ids)
    return source, ids


def seal(admin: Login, scope: tuple[UUID, UUID], count: int) -> dict[str, Any]:
    response = admin.client.post(
        "/api/v1/correlations/replay/finalize",
        json={"dataset_id": str(scope[0]), "run_id": str(scope[1]), "expected_event_count": count},
        headers=admin.authorization,
    )
    assert response.status_code == 200, response.text
    return response.json()
