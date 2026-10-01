"""Real PostgreSQL rollback, integrity, replay deduplication and bounded checkpoints."""

import hashlib
from copy import deepcopy
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.modules.alerts.models import Alert
from app.modules.audit.models import AuditLog
from app.modules.detections.models import DetectionJob, RuleDeployment
from app.modules.detections.processing import RuleConfigurationError, process_once
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.models import NormalizedEvent, PipelineJob

from .helper_ingestion import processing_database
from .helpers import Case, Login
from .test_initial_alerts import RULE, alerts, normalize_events, powershell

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("corruption", ["hash", "schema", "identity", "timestamp"])
def test_corrupted_normalized_evidence_is_quarantined(
    case: Case, admin: Login, corruption: str
) -> None:
    event_id = normalize_events(case, admin, [powershell()])[0]
    with Session(case.database.owner) as session:
        snapshot = session.get(NormalizedEvent, event_id)
        assert snapshot is not None
        document = deepcopy(snapshot.document)
        if corruption == "schema":
            document["timestamp"] = "not-a-time"
        elif corruption == "identity":
            document["event_id"] = "00000000-0000-0000-0000-000000000001"
        elif corruption == "timestamp":
            document["timestamp"] = "2020-01-01T00:00:00Z"
        session.execute(
            update(NormalizedEvent)
            .where(NormalizedEvent.event_id == event_id)
            .values(
                document=document,
                document_sha256="0" * 64
                if corruption == "hash"
                else hashlib.sha256(canonical_json(document)).hexdigest(),
            )
        )
        session.commit()
    result = process_once(processing_database(case), case.database.settings)
    assert result == {"processed": 0, "quarantined": 1, "alerts": 0}
    assert alerts(case) == []
    with Session(case.database.runtime) as session:
        job = session.get(DetectionJob, event_id)
        assert job is not None and job.state == "quarantined"
        assert job.error_code == "integrity_mismatch" and job.processed_at is not None
    assert process_once(processing_database(case), case.database.settings)["quarantined"] == 0


@pytest.mark.parametrize("corruption", ["missing", "version"])
def test_invalid_deployment_leaves_durable_job_pending(
    case: Case, admin: Login, corruption: str
) -> None:
    event_id = normalize_events(case, admin, [powershell()])[0]
    with Session(case.database.owner) as session:
        deployment = session.get(RuleDeployment, RULE)
        assert deployment is not None
        if corruption == "missing":
            session.delete(deployment)
        else:
            deployment.rule_version = "unknown"
        session.commit()
    with pytest.raises(RuleConfigurationError, match="rule_configuration_mismatch"):
        process_once(processing_database(case), case.database.settings)
    assert alerts(case) == []
    with Session(case.database.runtime) as session:
        job = session.get(DetectionJob, event_id)
        assert job is not None and job.state == "pending" and job.processed_at is None


def test_alert_audit_and_checkpoint_rollback_then_recover(
    case: Case, admin: Login, monkeypatch: pytest.MonkeyPatch
) -> None:
    event_id = normalize_events(case, admin, [powershell()])[0]

    def fail(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("planned-audit-failure")

    with monkeypatch.context() as patch:
        patch.setattr("app.modules.detections.processing.append_audit", fail)
        with pytest.raises(RuntimeError, match="planned-audit-failure"):
            process_once(processing_database(case), case.database.settings)
    assert alerts(case) == []
    with Session(case.database.runtime) as session:
        job = session.get(DetectionJob, event_id)
        assert job is not None and job.state == "pending"
    assert process_once(processing_database(case), case.database.settings)["alerts"] == 1
    assert len(alerts(case)) == 1


def test_replayed_checkpoint_does_not_duplicate_alert_or_audit(case: Case, admin: Login) -> None:
    event_id = normalize_events(case, admin, [powershell()])[0]
    database = processing_database(case)
    assert process_once(database, case.database.settings)["alerts"] == 1
    original = alerts(case)[0]
    with Session(case.database.owner) as session:
        session.execute(
            update(DetectionJob).where(DetectionJob.event_id == event_id).values(state="pending")
        )
        session.commit()
    assert process_once(database, case.database.settings) == {
        "processed": 1,
        "quarantined": 0,
        "alerts": 0,
    }
    assert alerts(case)[0].id == original.id
    assert alerts(case)[0].created_at == original.created_at
    with Session(case.database.runtime) as session:
        records = list(session.scalars(select(AuditLog).where(AuditLog.action == "alert.created")))
        assert len(records) == 1 and records[0].object_id == str(original.id)


def test_archive_failure_does_not_block_detection_and_batches_are_bounded(
    case: Case, admin: Login
) -> None:
    event_ids = normalize_events(case, admin, [powershell() for _ in range(3)])
    with Session(case.database.owner) as session:
        session.execute(
            update(PipelineJob)
            .where(PipelineJob.event_id.in_(event_ids))
            .values(state="projection_failed")
        )
        session.commit()
    settings = case.database.settings.model_copy(
        update={"pipeline_batch_size": 1, "clickhouse_url": "http://127.0.0.1:1"}
    )
    database = processing_database(case)
    for expected in (1, 2, 3):
        assert process_once(database, settings) == {"processed": 1, "quarantined": 0, "alerts": 1}
        assert len(alerts(case)) == expected
    assert process_once(database, settings) == {"processed": 0, "quarantined": 0, "alerts": 0}
    with Session(case.database.runtime) as session:
        assert len(list(session.scalars(select(Alert)))) == 3
