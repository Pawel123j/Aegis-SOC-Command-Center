"""Source-verified, idempotent indexes committed with normalization and alert evidence."""

import hashlib
import hmac
from typing import Any
from uuid import UUID

from sqlalchemy import exists, func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.modules.alerts.evidence import verified_events
from app.modules.alerts.models import Alert
from app.modules.audit.service import append_audit
from app.modules.entities.identity import IDENTITY_POLICY, extract_entity_descriptors
from app.modules.entities.models import (
    AlertEventReference,
    EntityAlertReceipt,
    EntityIdentity,
    EntityIndexReceipt,
    EntityObservation,
)
from app.modules.entities.schemas import BackfillResult, IndexStatus
from app.modules.ingestion.models import RawEvent
from app.modules.ingestion.processing import (
    EventSnapshot,
    PermanentProcessingError,
    validate_raw_event,
)
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.models import NormalizedEvent
from app.modules.normalization.schemas import NormalizedSecurityEvent


def verified_document(snapshot: NormalizedEvent, raw: RawEvent) -> NormalizedSecurityEvent:
    try:
        validate_raw_event(
            EventSnapshot(
                raw.id, raw.envelope, raw.payload_hash, raw.payload_bytes, raw.source_type
            )
        )
    except PermanentProcessingError:
        raise ValueError("entity_evidence_integrity_mismatch") from None
    if not hmac.compare_digest(
        hashlib.sha256(canonical_json(snapshot.document)).hexdigest(), snapshot.document_sha256
    ):
        raise ValueError("entity_evidence_integrity_mismatch")
    event = NormalizedSecurityEvent.model_validate(snapshot.document)
    if (
        event.event_id != snapshot.event_id
        or event.event_id != raw.id
        or event.timestamp != snapshot.timestamp
        or event.processed_at != snapshot.processed_at
        or event.received_at != raw.received_at
        or event.source_id != raw.source_id
        or event.dataset_id != raw.dataset_id
        or event.run_id != raw.run_id
        or event.mode != raw.mode
        or event.source.type != raw.source_type
        or event.raw_sha256 != raw.payload_hash
        or event.schema_version != snapshot.schema_version
        or event.parser_version != snapshot.parser_version
        or event.raw_event != raw.envelope["raw_event"]
        or event.source_event_id != raw.source_event_id
    ):
        raise ValueError("entity_evidence_integrity_mismatch")
    return event


def index_event(db: Session, snapshot: NormalizedEvent, raw: RawEvent | None = None) -> int:
    """A receipt is also recorded for a verified document with no observable entities."""
    raw = raw or db.get(RawEvent, snapshot.event_id)
    if raw is None:
        raise ValueError("entity_evidence_integrity_mismatch")
    event = verified_document(snapshot, raw)
    descriptors = extract_entity_descriptors(snapshot.document)
    inserted = db.scalar(
        insert(EntityIndexReceipt)
        .values(
            event_id=event.event_id,
            document_sha256=snapshot.document_sha256,
            identity_policy=IDENTITY_POLICY,
            observation_count=len(descriptors),
        )
        .on_conflict_do_nothing(index_elements=[EntityIndexReceipt.event_id])
        .returning(EntityIndexReceipt.event_id)
    )
    if inserted is None:
        prior = db.get(EntityIndexReceipt, event.event_id)
        if (
            prior is None
            or prior.document_sha256 != snapshot.document_sha256
            or prior.identity_policy != IDENTITY_POLICY
        ):
            raise ValueError("entity_index_integrity_mismatch")
        return 0
    for item in descriptors:
        source_id = None if item.entity_type == "ip" else event.source_id
        values: dict[str, Any] = {
            "id": item.entity_id,
            "key_sha256": item.key_sha256,
            "kind": item.entity_type,
            "label": item.label,
            "identity_policy": item.policy_version,
            "identity_basis": item.identity_strength,
            "canonical_identity": item.canonical_key,
            "source_id": source_id,
            "mode": event.mode,
            "dataset_id": event.dataset_id if event.mode == "replay" else None,
            "run_id": event.run_id,
        }
        db.execute(
            insert(EntityIdentity)
            .values(**values)
            .on_conflict_do_nothing(index_elements=[EntityIdentity.id])
        )
        stored = db.get(EntityIdentity, item.entity_id)
        # Labels are first-observed display facts, not immutable identity components.
        # A later rename is stored in its observation without rewriting the identity.
        if stored is None or any(
            getattr(stored, key) != value for key, value in values.items() if key != "label"
        ):
            raise ValueError("entity_identity_integrity_mismatch")
        db.execute(
            insert(EntityObservation).values(
                entity_id=item.entity_id,
                event_id=event.event_id,
                role=item.role,
                timestamp=event.timestamp,
                document_sha256=snapshot.document_sha256,
                attributes={
                    **item.attributes,
                    **(
                        {f"{item.entity_type}_name": item.attributes["name"]}
                        if item.entity_type in {"user", "process"} and "name" in item.attributes
                        else {}
                    ),
                },
            )
        )
    return len(descriptors)


def index_alert(db: Session, alert: Alert, *, ensure_existing_events: bool = False) -> None:
    events = verified_events(alert)
    if not 1 <= len(events) <= 100:
        raise ValueError("entity_alert_integrity_mismatch")
    rows = db.execute(
        select(NormalizedEvent, RawEvent)
        .join(RawEvent, RawEvent.id == NormalizedEvent.event_id)
        .where(NormalizedEvent.event_id.in_([item.event_id for item in events]))
    ).all()
    snapshots = {item.event_id: (item, raw) for item, raw in rows}
    if len(snapshots) != len(events):
        raise ValueError("entity_alert_integrity_mismatch")
    for event in events:
        snapshot, raw = snapshots[event.event_id]
        verified_document(snapshot, raw)
        if event.model_dump(mode="json") != snapshot.document:
            raise ValueError("entity_alert_integrity_mismatch")
        if ensure_existing_events:
            receipt = db.get(EntityIndexReceipt, event.event_id)
            if (
                receipt is None
                or receipt.document_sha256 != snapshot.document_sha256
                or receipt.identity_policy != IDENTITY_POLICY
            ):
                raise ValueError("entity_alert_requires_indexed_events")
        else:
            index_event(db, snapshot, raw)
    inserted = db.scalar(
        insert(EntityAlertReceipt)
        .values(
            alert_id=alert.id,
            contributor_count=len(events),
        )
        .on_conflict_do_nothing(index_elements=[EntityAlertReceipt.alert_id])
        .returning(EntityAlertReceipt.alert_id)
    )
    if inserted is None:
        prior = db.get(EntityAlertReceipt, alert.id)
        if prior is None or prior.contributor_count != len(events):
            raise ValueError("entity_alert_integrity_mismatch")
        return
    db.execute(
        insert(AlertEventReference),
        [
            {
                "alert_id": alert.id,
                "event_id": item.event_id,
                "document_sha256": snapshots[item.event_id][0].document_sha256,
            }
            for item in events
        ],
    )


def global_index_status(db: Session) -> IndexStatus:
    events = int(
        db.scalar(
            select(func.count())
            .select_from(NormalizedEvent)
            .where(
                ~exists(
                    select(EntityIndexReceipt.event_id).where(
                        EntityIndexReceipt.event_id == NormalizedEvent.event_id
                    )
                )
            )
        )
        or 0
    )
    alerts = int(
        db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(
                ~exists(
                    select(EntityAlertReceipt.alert_id).where(
                        EntityAlertReceipt.alert_id == Alert.id
                    )
                )
            )
        )
        or 0
    )
    return IndexStatus(pending_events=events, pending_alerts=alerts, complete=events == alerts == 0)


def backfill(db: Session, limit: int, *, actor_id: UUID, request_id: str) -> BackfillResult:
    db.execute(text("SET LOCAL statement_timeout = '3000ms'"))
    records = db.execute(
        select(NormalizedEvent, RawEvent)
        .join(RawEvent, RawEvent.id == NormalizedEvent.event_id)
        .where(
            ~exists(
                select(EntityIndexReceipt.event_id).where(
                    EntityIndexReceipt.event_id == NormalizedEvent.event_id
                )
            )
        )
        .order_by(NormalizedEvent.processed_at, NormalizedEvent.event_id)
        .limit(limit)
    ).all()
    try:
        observations = sum(index_event(db, snapshot, raw) for snapshot, raw in records)
        # Old contributor sets become eligible only after the explicit event phase.
        # A request never indexes hidden events through an alert, and at most100
        # contributor snapshots are loaded across its entire alert phase.
        # Select small metadata first; do not materialize100 full alert arrays.
        rows = db.execute(
            text("""
          SELECT a.id,CASE WHEN jsonb_array_length(a.event_snapshots)=0 THEN 1
            ELSE jsonb_array_length(a.event_snapshots) END AS contributor_count
          FROM public.alerts a WHERE NOT EXISTS (
            SELECT 1 FROM public.entity_alert_receipts p WHERE p.alert_id=a.id)
          ORDER BY a.created_at,a.id LIMIT :limit
        """),
            {"limit": limit},
        ).all()
        alerts = []
        proof_budget = 100
        for identifier, count in rows:
            if count > proof_budget:
                break
            proof_budget -= count
            alert = db.get(Alert, identifier)
            assert alert is not None
            event_ids = [item.event_id for item in verified_events(alert)]
            indexed = int(
                db.scalar(
                    select(func.count())
                    .select_from(EntityIndexReceipt)
                    .where(EntityIndexReceipt.event_id.in_(event_ids))
                )
                or 0
            )
            if indexed != len(event_ids):
                continue
            alerts.append(alert)
        for alert in alerts:
            index_alert(db, alert, ensure_existing_events=True)
    except (KeyError, TypeError, ValueError):
        raise ApiError(
            409,
            "entity_evidence_integrity_mismatch",
            "Entity indexing requires verified immutable evidence",
        ) from None
    status = global_index_status(db)
    append_audit(
        db,
        action="entities.backfilled",
        outcome="success",
        actor_id=actor_id,
        request_id=request_id,
        object_type="entity_index",
        details={
            "events": len(records),
            "alerts": len(alerts),
            "observations": observations,
            "identity_policy": IDENTITY_POLICY,
        },
    )
    return BackfillResult(
        events=len(records),
        alerts=len(alerts),
        observations=observations,
        index_status=status,
        identity_policy=IDENTITY_POLICY,
    )
