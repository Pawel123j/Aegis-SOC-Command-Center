"""Frozen alert references and current eligible case associations share source proof."""

import hashlib
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.modules.alerts.evidence import verified_events
from app.modules.alerts.models import Alert
from app.modules.correlation.builtin import BUILTIN_RULES as CORRELATION_RULES
from app.modules.detections.builtin import BUILTIN_RULES
from app.modules.incidents.models import IncidentAlert
from app.modules.ingestion.schemas import canonical_json
from app.modules.mitre.catalogue import CATALOGUE_SHA256
from app.modules.mitre.mapping import associate, legacy_mapping, rule_mapping
from app.modules.mitre.models import AlertMitreMapping, AlertMitreSnapshot
from app.modules.mitre.schemas import IncidentMapping, IncidentTechnique, MappingView
from app.modules.sigma.compiler import EVALUATOR_VERSION as SIGMA_EVALUATOR
from app.modules.sigma.service import mapping as sigma_mapping
from app.modules.sigma.service import verified_alert


def _input_hash(alert: Alert) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "detection_key": alert.detection_key,
                "rule_id": alert.rule_id,
                "rule_version": alert.rule_version,
                "evaluator_version": alert.evaluator_version,
                "event_id": str(alert.event_id),
                "source_id": str(alert.source_id),
                "dataset_id": str(alert.dataset_id),
                "run_id": str(alert.run_id),
                "mode": alert.mode,
                "event_timestamp": alert.event_timestamp.isoformat(),
                "severity": alert.severity,
                "title": alert.title,
                "rule_snapshot": alert.rule_snapshot,
                "event_snapshot": alert.event_snapshot,
                "event_sha256": alert.event_sha256,
                "event_snapshots": alert.event_snapshots,
            }
        )
    ).hexdigest()


def record_mapping(db: Session, alert: Alert) -> None:
    """Called only after controlled worker evaluation, before the same commit."""
    try:
        verified_events(alert)
        if alert.evaluator_version == SIGMA_EVALUATOR:
            view = sigma_mapping(verified_alert(db, alert))
        else:
            rule = next(
                (item for item in (*BUILTIN_RULES, *CORRELATION_RULES) if item.id == alert.rule_id),
                None,
            )
            frozen = {k: v for k, v in alert.rule_snapshot.items() if k != "deployment_version"}
            if (
                rule is None
                or frozen != rule.snapshot()
                or alert.rule_version != rule.version
                or alert.evaluator_version != frozen["evaluator_version"]
                or alert.severity != rule.severity
            ):
                raise ValueError("untrusted association rule")
            view = rule_mapping(alert.rule_id)
        document = view.model_dump(mode="json")
        input_hash = _input_hash(alert)
        prior = db.get(AlertMitreSnapshot, alert.id)
        if prior is not None:
            if prior.input_sha256 != input_hash or prior.document != document:
                raise ValueError("immutable mapping already recorded")
            return
        assert view.catalogue_version and view.catalogue_hash
        assert view.mapping_version and view.mapping_hash
        db.add(
            AlertMitreSnapshot(
                alert_id=alert.id,
                status=view.status,
                catalogue_version=view.catalogue_version,
                catalogue_hash=view.catalogue_hash,
                mapping_version=view.mapping_version,
                mapping_hash=view.mapping_hash,
                input_sha256=input_hash,
                snapshot_sha256=hashlib.sha256(canonical_json(document)).hexdigest(),
                document=document,
            )
        )
        db.flush()
        db.add_all(
            AlertMitreMapping(alert_id=alert.id, technique_id=technique.id, tactic_id=tactic.id)
            for technique in view.techniques
            for tactic in technique.tactics
        )
        db.flush()
    except (KeyError, TypeError, ValueError):
        raise ApiError(
            409, "mitre_evidence_integrity_mismatch", "MITRE requires supported immutable proof"
        ) from None


def snapshot_view(row: AlertMitreSnapshot) -> MappingView:
    try:
        if hashlib.sha256(canonical_json(row.document)).hexdigest() != row.snapshot_sha256:
            raise ValueError("snapshot hash mismatch")
        view = MappingView.model_validate(row.document)
        if (
            view.status != row.status
            or view.catalogue_version != row.catalogue_version
            or view.catalogue_hash != row.catalogue_hash
            or view.mapping_version != row.mapping_version
            or view.mapping_hash != row.mapping_hash
        ):
            raise ValueError("snapshot metadata mismatch")
        if view.catalogue_hash == CATALOGUE_SHA256 and view.techniques != associate(
            item.id for item in view.techniques
        ):
            raise ValueError("snapshot technique or tactic mismatch")
        return view
    except (KeyError, TypeError, ValueError):
        raise ApiError(
            409, "mitre_snapshot_integrity_mismatch", "MITRE snapshot is invalid"
        ) from None


def alert_mapping(db: Session, alert: Alert) -> MappingView:
    row = db.get(AlertMitreSnapshot, alert.id)
    if row is None:
        return legacy_mapping()
    try:
        verified_events(alert)
        if alert.evaluator_version == SIGMA_EVALUATOR:
            verified_alert(db, alert)
    except (KeyError, TypeError, ValueError):
        raise ApiError(
            409, "mitre_evidence_integrity_mismatch", "MITRE source proof changed"
        ) from None
    if _input_hash(alert) != row.input_sha256:
        raise ApiError(409, "mitre_evidence_integrity_mismatch", "MITRE source proof changed")
    return snapshot_view(row)


def incident_mapping(db: Session, incident_id: UUID) -> IncidentMapping:
    records = db.execute(
        select(Alert, AlertMitreSnapshot)
        .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
        .outerjoin(AlertMitreSnapshot, AlertMitreSnapshot.alert_id == Alert.id)
        .where(IncidentAlert.incident_id == incident_id, IncidentAlert.active.is_(True))
        .order_by(Alert.id)
        .limit(101)
    ).all()
    if len(records) > 100:
        raise ApiError(409, "mitre_case_limit", "Case exceeds bounded MITRE evidence limit")
    techniques: dict[tuple[str, str], IncidentTechnique] = {}
    counts = {"mapped": 0, "unmapped": 0, "legacy_unmapped": 0, "excluded": 0}
    for alert, row in records:
        if alert.status == "false_positive":
            counts["excluded"] += 1
            continue
        view = alert_mapping(db, alert) if row else legacy_mapping()
        counts[view.status] += 1
        for technique in view.techniques:
            assert view.catalogue_hash and view.catalogue_version
            techniques[(view.catalogue_hash, technique.id)] = IncidentTechnique(
                **technique.model_dump(),
                catalogue_version=view.catalogue_version,
                catalogue_hash=view.catalogue_hash,
            )
    return IncidentMapping(
        techniques=[value for _, value in sorted(techniques.items())],
        mapped_alerts=counts["mapped"],
        unmapped_alerts=counts["unmapped"],
        legacy_alerts=counts["legacy_unmapped"],
        excluded_false_positive_alerts=counts["excluded"],
    )
