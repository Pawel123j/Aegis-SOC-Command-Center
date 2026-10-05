"""Source-verified local matches frozen at first evaluation, including empty results."""

import hashlib
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import exists, func, select
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.infrastructure.database import utcnow
from app.modules.alerts.evidence import verified_events
from app.modules.alerts.models import Alert
from app.modules.audit.service import append_audit
from app.modules.entities.indexing import verified_document
from app.modules.ingestion.models import RawEvent
from app.modules.ingestion.schemas import canonical_json
from app.modules.intelligence.contracts import (
    EVALUATOR_VERSION,
    RULE_ID,
    RULE_VERSION,
    IntelligenceMatch,
    IntelligenceRule,
    rule_snapshot,
)
from app.modules.intelligence.extraction import extract_indicators
from app.modules.intelligence.models import IntEventMatch, IntEventReceipt, IOCRevision
from app.modules.intelligence.normalization import NORMALIZATION_VERSION
from app.modules.intelligence.service import active_iocs, revision_document
from app.modules.normalization.models import NormalizedEvent
from app.modules.normalization.schemas import NormalizedSecurityEvent
from app.modules.risk.schemas import ContextFact, Provenance


def _source(db: Session, snapshot: NormalizedEvent) -> NormalizedSecurityEvent:
    raw = db.get(RawEvent, snapshot.event_id)
    if raw is None:
        raise ValueError("intelligence_source_integrity_mismatch")
    return verified_document(snapshot, raw)


def _match_view(row: IntEventMatch) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "event_id": str(row.event_id),
        "ioc_id": str(row.ioc_id),
        "revision_id": str(row.revision_id),
        "field": row.field,
        "observed_value": row.observed_value,
        "canonical_value": row.canonical_value,
        "revision_snapshot": row.revision_snapshot,
        "revision_snapshot_sha256": row.revision_snapshot_sha256,
    }


def _verify_match(
    row: IntEventMatch, revision: IOCRevision, indicators: list[dict[str, str]]
) -> None:
    document = revision_document(revision)
    if (
        row.ioc_id != revision.ioc_id
        or row.revision_id != revision.id
        or row.revision_snapshot != document
        or row.revision_snapshot_sha256 != revision.document_sha256
        or not document["active"]
        or row.canonical_value != document["canonical_value"]
        or not any(
            item["type"] == document["type"]
            and item["value"] == row.canonical_value
            and item["field"] == row.field
            and item["observed_value"] == row.observed_value
            for item in indicators
        )
    ):
        raise ValueError("intelligence_match_integrity_mismatch")


def _verify_receipt(
    receipt: IntEventReceipt, snapshot: NormalizedEvent, event: NormalizedSecurityEvent, count: int
) -> None:
    if (
        receipt.event_id != event.event_id
        or receipt.document_sha256 != snapshot.document_sha256
        or receipt.normalization_version != NORMALIZATION_VERSION
        or receipt.mode != event.mode
        or receipt.dataset_id != (event.dataset_id if event.mode == "replay" else None)
        or receipt.run_id != event.run_id
        or receipt.match_count != count
        or not 0 <= count <= 32
        or receipt.evaluated_at.tzinfo is None
    ):
        raise ValueError("intelligence_receipt_integrity_mismatch")


def _frozen(
    db: Session, snapshot: NormalizedEvent, event: NormalizedSecurityEvent
) -> tuple[IntEventReceipt, list[IntEventMatch]] | None:
    receipt = db.get(IntEventReceipt, event.event_id)
    if receipt is None:
        return None
    rows = list(
        db.scalars(
            select(IntEventMatch)
            .where(IntEventMatch.event_id == event.event_id)
            .order_by(IntEventMatch.revision_id, IntEventMatch.field, IntEventMatch.id)
            .limit(33)
        )
    )
    _verify_receipt(receipt, snapshot, event, len(rows))
    revisions = {
        item.id: item
        for item in db.scalars(
            select(IOCRevision).where(IOCRevision.id.in_([row.revision_id for row in rows]))
        )
    }
    indicators = extract_indicators(event)
    for row in rows:
        revision = revisions.get(row.revision_id)
        if revision is None:
            raise ValueError("intelligence_revision_integrity_mismatch")
        _verify_match(row, revision, indicators)
    return receipt, rows


def evaluate_event(db: Session, snapshot: NormalizedEvent) -> list[IntEventMatch]:
    """Caller holds the shared authority lock and commits this ledger with its job."""
    event = _source(db, snapshot)
    prior = _frozen(db, snapshot, event)
    if prior is not None:
        return prior[1]
    catalog = {(row.document["type"], row.document["value"]): row for row in active_iocs(db)}
    found = []
    for item in extract_indicators(event):
        revision = catalog.get((item["type"], item["value"]))
        if revision is not None:
            found.append(
                IntEventMatch(
                    id=uuid4(),
                    event_id=event.event_id,
                    ioc_id=revision.ioc_id,
                    revision_id=revision.id,
                    field=item["field"],
                    observed_value=item["observed_value"],
                    canonical_value=item["value"],
                    revision_snapshot=revision_document(revision),
                    revision_snapshot_sha256=revision.document_sha256,
                )
            )
    db.add(
        IntEventReceipt(
            event_id=event.event_id,
            document_sha256=snapshot.document_sha256,
            normalization_version=NORMALIZATION_VERSION,
            mode=event.mode,
            dataset_id=event.dataset_id if event.mode == "replay" else None,
            run_id=event.run_id,
            match_count=len(found),
            evaluated_at=utcnow(),
        )
    )
    db.flush()
    db.add_all(found)
    db.flush()
    return found


def frozen_event(db: Session, event_id: UUID) -> dict[str, Any]:
    snapshot = db.get(NormalizedEvent, event_id)
    if snapshot is None:
        raise ApiError(404, "event_not_found", "Normalized event not found")
    try:
        event = _source(db, snapshot)
        frozen = _frozen(db, snapshot, event)
        receipt, rows = frozen if frozen is not None else (None, [])
        return {
            "event_id": str(event_id),
            "status": "evaluated" if receipt is not None else "pending",
            "normalization_version": NORMALIZATION_VERSION,
            "evaluator_version": EVALUATOR_VERSION,
            "document_sha256": snapshot.document_sha256,
            "evaluated_at": receipt.evaluated_at.isoformat() if receipt else None,
            "matches": [_match_view(row) for row in rows],
            "match_count": len(rows),
            "reputation_origin": "source_assertion",
            "confirmed_attack": False,
        }
    except (KeyError, TypeError, ValueError):
        raise ApiError(
            409, "intelligence_evidence_integrity_mismatch", "Stored match proof is invalid"
        ) from None


def alert_match(
    db: Session, snapshot: NormalizedEvent, deployment_version: int
) -> IntelligenceMatch | None:
    proof = frozen_event(db, snapshot.event_id)
    matches = [
        row for row in proof["matches"] if row["revision_snapshot"]["reputation"] == "malicious"
    ]
    if not matches:
        return None
    reason = {**proof, "matches": matches, "match_count": len(matches)}
    reason["proof_sha256"] = hashlib.sha256(canonical_json(reason)).hexdigest()
    return IntelligenceMatch(IntelligenceRule(deployment_version), reason)


def verified_alert(db: Session, alert: Alert) -> None:
    events = verified_events(alert)
    frozen_rule = {k: v for k, v in alert.rule_snapshot.items() if k != "deployment_version"}
    snapshot = db.get(NormalizedEvent, alert.event_id)
    if (
        alert.rule_id != RULE_ID
        or alert.rule_version != RULE_VERSION
        or alert.evaluator_version != EVALUATOR_VERSION
        or frozen_rule != rule_snapshot()
        or alert.severity != "medium"
        or alert.title != rule_snapshot()["title"]
        or len(events) != 1
        or snapshot is None
        or events[0].model_dump(mode="json") != snapshot.document
        or type(alert.rule_snapshot.get("deployment_version")) is not int
        or alert.rule_snapshot["deployment_version"] < 1
    ):
        raise ValueError("intelligence_alert_integrity_mismatch")
    match = alert_match(db, snapshot, alert.rule_snapshot["deployment_version"])
    if match is None or match.reason != alert.reason:
        raise ValueError("intelligence_alert_integrity_mismatch")


def backfill(db: Session, limit: int, *, actor_id: UUID, request_id: str) -> dict[str, Any]:
    rows = list(
        db.scalars(
            select(NormalizedEvent)
            .where(
                ~exists(
                    select(IntEventReceipt.event_id).where(
                        IntEventReceipt.event_id == NormalizedEvent.event_id
                    )
                )
            )
            .order_by(NormalizedEvent.processed_at, NormalizedEvent.event_id)
            .limit(limit)
        )
    )
    try:
        matched = sum(len(evaluate_event(db, row)) for row in rows)
    except (KeyError, TypeError, ValueError):
        raise ApiError(
            409, "intelligence_evidence_integrity_mismatch", "Source proof is invalid"
        ) from None
    remaining = int(
        db.scalar(
            select(func.count())
            .select_from(NormalizedEvent)
            .where(
                ~exists(
                    select(IntEventReceipt.event_id).where(
                        IntEventReceipt.event_id == NormalizedEvent.event_id
                    )
                )
            )
        )
        or 0
    )
    result = {
        "events": len(rows),
        "matches": matched,
        "remaining": remaining,
        "evaluator_version": EVALUATOR_VERSION,
        "alerts_created": 0,
    }
    append_audit(
        db,
        action="intelligence.backfill",
        outcome="success",
        actor_id=actor_id,
        request_id=request_id,
        object_type="intelligence",
        details=result,
    )
    return result


def risk_contexts(
    db: Session, events: dict[UUID, NormalizedSecurityEvent]
) -> tuple[list[ContextFact], dict[str, Any]]:
    """At most 100 strongest field matches; max-I arithmetic remains exact if truncated."""
    if not events:
        return [], {"selected_matches": 0, "available_matches": 0, "truncated": False}
    # Immutable inputs are bounded at 10,000 events. Fetching every 32KB revision
    # for every field could exceed 10GB, so rank before fetching snapshots.
    from sqlalchemy import case

    reputation = IntEventMatch.revision_snapshot["reputation"].as_string()
    confidence = IntEventMatch.revision_snapshot["confidence"].as_integer()
    points = case(
        ((reputation == "malicious") & (confidence >= 80), 15),
        ((reputation == "suspicious") & (confidence >= 50), 8),
        (reputation == "malicious", 5),
        else_=0,
    )
    records = db.execute(
        select(IntEventMatch, func.count().over().label("total"))
        .where(IntEventMatch.event_id.in_(list(events)))
        .order_by(
            points.desc(), IntEventMatch.revision_id, IntEventMatch.event_id, IntEventMatch.field
        )
        .limit(100)
    ).all()
    rows = [row for row, _ in records]
    total = int(records[0][1]) if records else 0
    selected = {row.event_id for row in rows}
    revisions = {
        row.id: row
        for row in db.scalars(
            select(IOCRevision).where(IOCRevision.id.in_([row.revision_id for row in rows]))
        )
    }
    snapshots = {
        row.event_id: (row, raw)
        for row, raw in db.execute(
            select(NormalizedEvent, RawEvent)
            .join(RawEvent, RawEvent.id == NormalizedEvent.event_id)
            .where(NormalizedEvent.event_id.in_(selected))
        )
    }
    receipts = {
        row.event_id: row
        for row in db.scalars(select(IntEventReceipt).where(IntEventReceipt.event_id.in_(selected)))
    }
    counts = {
        identity: count
        for identity, count in db.execute(
            select(IntEventMatch.event_id, func.count())
            .where(IntEventMatch.event_id.in_(selected))
            .group_by(IntEventMatch.event_id)
        ).all()
    }
    indicators = {}
    for identity in selected:
        snapshot, raw = snapshots[identity]
        event = verified_document(snapshot, raw)
        if event.model_dump(mode="json") != events[identity].model_dump(mode="json"):
            raise ValueError("intelligence_risk_scope_mismatch")
        _verify_receipt(receipts[identity], snapshot, event, counts[identity])
        indicators[identity] = extract_indicators(event)
    facts = []
    for row in rows:
        revision = revisions[row.revision_id]
        _verify_match(row, revision, indicators[row.event_id])
        facts.append(
            ContextFact(
                kind="ioc_reputation",
                value=row.revision_snapshot["reputation"],
                confidence=row.revision_snapshot["confidence"],
                evidence_ids=[row.event_id],
                provenance=Provenance(
                    source="local-ioc-revision:" + str(row.revision_id),
                    version=NORMALIZATION_VERSION,
                    snapshot_sha256=row.revision_snapshot_sha256,
                    as_of=receipts[row.event_id].evaluated_at,
                ),
            )
        )
    return facts, {
        "selected_matches": len(rows),
        "available_matches": total,
        "truncated": total > len(rows),
        "selection": "highest-i-points-then-revision-event-field",
        "maximum": 100,
    }
