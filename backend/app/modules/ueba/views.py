"""Verify original sources and every indexed role before producing statistics."""

import hashlib
from datetime import datetime
from typing import Any
from uuid import UUID, uuid5

from app.core.errors import ApiError
from app.modules.entities.identity import (
    IDENTITY_NAMESPACE,
    IDENTITY_POLICY,
    extract_entity_descriptors,
)
from app.modules.entities.indexing import verified_document
from app.modules.ingestion.models import RawEvent
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.models import NormalizedEvent
from app.modules.ueba import queries, statistics
from app.modules.ueba.schemas import UebaEntity, UebaFilters, UebaReport, UebaScope


def _verified(row: dict[str, Any], identity: dict[str, Any]) -> statistics.VerifiedEvent:
    normalized, raw = dict(row["normalized"]), dict(row["raw"])
    normalized["event_id"] = UUID(normalized["event_id"])
    for key in ("timestamp", "processed_at"):
        normalized[key] = datetime.fromisoformat(normalized[key])
    for key in ("id", "source_id", "dataset_id", "run_id"):
        raw[key] = UUID(raw[key])
    raw["received_at"] = datetime.fromisoformat(raw["received_at"])
    snapshot = NormalizedEvent(**normalized)
    event = verified_document(snapshot, RawEvent(**raw))
    descriptors = extract_entity_descriptors(event)
    receipt = row["receipt"]
    expected = {(str(d.entity_id), d.role): d for d in descriptors}
    observed = {(o["entity_id"], o["role"]): o for o in row["observations"]}
    if (
        receipt["event_id"] != str(event.event_id)
        or receipt["document_sha256"] != snapshot.document_sha256
        or receipt["identity_policy"] != IDENTITY_POLICY
        or receipt["observation_count"] != len(descriptors)
        or len(row["observations"]) != len(observed)
        or set(expected) != set(observed)
    ):
        raise ValueError("index mismatch")
    matched = False
    for role_key, descriptor in expected.items():
        observation = observed[role_key]
        if (
            observation["event_id"] != str(event.event_id)
            or datetime.fromisoformat(observation["timestamp"]) != event.timestamp
            or observation["document_sha256"] != snapshot.document_sha256
            or observation["attributes"] != descriptor.attributes
        ):
            raise ValueError("observation mismatch")
        if str(descriptor.entity_id) == identity["id"]:
            matched = True
            if (
                descriptor.canonical_key != identity["canonical_identity"]
                or descriptor.identity_strength != identity["identity_basis"]
                or descriptor.key_sha256 != identity["key_sha256"]
                or descriptor.entity_type != identity["kind"]
                or str(event.source_id) != identity["source_id"]
            ):
                raise ValueError("identity mismatch")
    if not matched:
        raise ValueError("membership mismatch")
    return statistics.VerifiedEvent(event, snapshot.document_sha256, descriptors)


def project(
    data: dict[str, Any],
    filters: UebaFilters,
    start: datetime,
    observed_start: datetime,
    end: datetime,
) -> UebaReport:
    identity = data["identity"]
    if identity is None:
        raise ApiError(404, "entity_not_found", "Entity not found in this scope")
    if data["event_count"] > queries.MAX_EVENTS or data["bytes"] > queries.MAX_BYTES:
        raise ApiError(409, "ueba_limit_exceeded", "The daily UEBA evidence exceeds its bounds")
    try:
        if data["integrity_mismatch"]:
            raise ValueError("index or scope mismatch")
        canonical = identity["canonical_identity"]
        digest = hashlib.sha256(canonical_json(canonical)).hexdigest()
        if (
            digest != identity["key_sha256"]
            or str(uuid5(IDENTITY_NAMESPACE, digest)) != identity["id"]
            or identity["identity_policy"] != IDENTITY_POLICY
            or canonical["kind"] != identity["kind"]
            or canonical["mode"] != filters.mode
            or canonical["policy"] != IDENTITY_POLICY
            or identity["mode"] != filters.mode
            or (identity["kind"] != "ip" and canonical.get("source_id") != identity["source_id"])
            or canonical["dataset_id"]
            != (str(filters.dataset_id) if filters.mode == "replay" else "")
            or canonical["run_id"]
            != str(filters.run_id if filters.mode == "replay" else UUID(int=0))
            or identity["dataset_id"]
            != (str(filters.dataset_id) if filters.mode == "replay" else None)
            or identity["run_id"]
            != str(filters.run_id if filters.mode == "replay" else UUID(int=0))
        ):
            raise ValueError("identity mismatch")
        events = [_verified(row, identity) for row in data["items"]]
        if len(events) != data["event_count"]:
            raise ValueError("incomplete evidence")
        return statistics.report(
            UebaEntity.model_validate(identity),
            UebaScope(
                mode=filters.mode,
                dataset_id=filters.dataset_id,
                run_id=filters.run_id if filters.mode == "replay" else None,
            ),
            events,
            start,
            observed_start,
            end,
            data["pending"],
            cross_host=identity["identity_basis"] == "source_scoped"
            and canonical.get("basis") == "windows_sid",
            as_of=datetime.fromisoformat(data["as_of"]),
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ApiError(
            409, "ueba_integrity_mismatch", "The daily UEBA evidence is invalid"
        ) from None
