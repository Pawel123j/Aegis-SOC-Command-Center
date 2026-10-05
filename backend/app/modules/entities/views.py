"""Validate bounded frozen projection payloads without changing historical scores."""

import hashlib
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.errors import ApiError
from app.modules.entities.schemas import (
    EntityDetail,
    EntityFilters,
    EntityMitre,
    EntityRisk,
    EntityScope,
    EntitySummary,
    EntityTechnique,
    IndexStatus,
)
from app.modules.ingestion.schemas import canonical_json
from app.modules.mitre.catalogue import CATALOGUE_SHA256, catalogue_view
from app.modules.risk.engine import POLICY_HASH, POLICY_VERSION
from app.modules.risk.models import RiskCalculation
from app.modules.risk.schemas import RiskInput
from app.modules.risk.service import calculation_view

_POLICIES = {
    "risk-policy-v2": "fe87d0dd228f33d01ce32434cd8ac6620f4cf1d3723ebd077ca2add7b466e85c",
    POLICY_VERSION: POLICY_HASH,
}


def status(raw: dict[str, Any]) -> IndexStatus:
    return IndexStatus(**raw, complete=raw["pending_events"] == raw["pending_alerts"] == 0)


def scope(filters: EntityFilters, params: dict[str, Any]) -> EntityScope:
    return EntityScope(
        mode=filters.mode,
        dataset_id=filters.dataset_id,
        run_id=filters.run_id,
        from_=params["start"],
        to=params["end"],
    )


def _timestamp(value: str | datetime) -> datetime:
    return datetime.fromisoformat(value) if isinstance(value, str) else value


def risk(raw: dict[str, Any]) -> EntityRisk:
    counts = raw["counts"]
    candidate = raw["risk"]
    calculation = None
    try:
        if raw["invalid_risk"]:
            raise ValueError("inconsistent current assessment")
        if candidate is not None:
            definition = candidate["calculation"]
            kwargs = {**definition}
            for key in ("id", "subject_id", "actor_id", "previous_id", "dataset_id", "run_id"):
                kwargs[key] = UUID(kwargs[key]) if kwargs[key] is not None else None
            kwargs["created_at"] = _timestamp(kwargs["created_at"])
            row = RiskCalculation(**kwargs)
            if (
                hashlib.sha256(canonical_json(row.input_snapshot)).hexdigest() != row.input_sha256
                or _POLICIES.get(row.policy_version) != row.policy_hash
                or row.subject_type != "alert"
                or str(row.subject_id) != candidate["alert_id"]
                or row.mode != raw["identity"]["mode"]
                or str(row.run_id) != raw["identity"]["run_id"]
                or (row.mode == "replay" and str(row.dataset_id) != raw["identity"]["dataset_id"])
            ):
                raise ValueError("invalid immutable assessment")
            scoring = RiskInput.model_validate(row.input_snapshot["scoring_input"])
            proof = {
                item["event_id"]: (item["sha256"], _timestamp(item["timestamp"]))
                for item in candidate["proof"]
            }
            if (
                len(proof) != len(candidate["proof"])
                or {str(item.id): (item.sha256, item.timestamp) for item in scoring.evidence}
                != proof
                or row.input_snapshot["source_alerts"] != [candidate["source"]]
                or row.input_snapshot["excluded_alert_ids"] != []
                or scoring.subject_id != row.subject_id
                or scoring.mode != row.mode
                or scoring.run_id != row.run_id
                or scoring.dataset_id != (row.dataset_id if row.mode == "replay" else None)
            ):
                raise ValueError("assessment source proof mismatch")
            calculation = calculation_view(row)
            if calculation.score != row.score or calculation.level != row.level:
                raise ValueError("assessment explanation mismatch")
    except (KeyError, TypeError, ValueError):
        raise ApiError(
            409, "entity_risk_integrity_mismatch", "Stored entity priority evidence is invalid"
        ) from None
    return EntityRisk(
        score=calculation.score if calculation else None,
        level=calculation.level if calculation else None,
        alert_id=calculation.subject_id if calculation else None,
        calculation_id=calculation.id if calculation else None,
        policy_version=calculation.policy_version if calculation else None,
        explanation=calculation.model_dump(mode="json") if calculation else None,
        eligible_alerts=counts["eligible_alerts"],
        assessed_alerts=raw["assessed_alerts"],
        excluded_false_positive_alerts=counts["false_positive_alerts"],
        reason=(
            "Maximum existing eligible alert assessment; scores are not summed "
            "and no entity score is calculated."
        )
        if calculation
        else "No current assessed eligible alert in this activity window.",
    )


def summary(raw: dict[str, Any]) -> EntitySummary:
    projected = risk(raw)
    identity = raw["identity"]
    return EntitySummary(
        id=identity["id"],
        kind=identity["kind"],
        label=raw["label"],
        identity_policy=identity["identity_policy"],
        identity_basis=identity["identity_basis"],
        source_id=identity["source_id"],
        first_seen=raw["first_seen"],
        last_seen=raw["last_seen"],
        counts=raw["counts"],
        risk_score=projected.score,
        risk_level=projected.level,
    )


def detail(raw: dict[str, Any], scoped: EntityScope, index_status: IndexStatus) -> EntityDetail:
    catalogue = catalogue_view()
    known = {item.id: item for item in catalogue.techniques}
    techniques = []
    for entry in raw["mitre"]["techniques"]:
        item = known.get(entry["id"])
        if item is None:
            raise ApiError(
                409, "entity_mitre_integrity_mismatch", "Stored entity associations are invalid"
            )
        techniques.append(
            EntityTechnique(
                id=item.id,
                name=item.name,
                url=item.url,
                catalogue_version=catalogue.catalogue.version,
                catalogue_hash=CATALOGUE_SHA256,
                alert_count=entry["alert_count"],
            )
        )
    return EntityDetail(
        **summary(raw).model_dump(),
        scope=scoped,
        canonical_identity=raw["identity"]["canonical_identity"],
        risk=risk(raw),
        mitre=EntityMitre(
            **{key: value for key, value in raw["mitre"].items() if key != "techniques"},
            techniques=techniques,
            excluded_false_positive_alerts=raw["counts"]["false_positive_alerts"],
        ),
        roles=raw["roles"],
        related_host_count=raw["related_host_count"],
        index_status=index_status,
    )
