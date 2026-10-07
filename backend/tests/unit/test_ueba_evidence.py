"""Independent corruption checks of immutable original and membership proofs."""

import hashlib
from copy import deepcopy
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from test_attack_timeline import NOW
from test_attack_timeline import fixture as timeline_fixture

from app.core.errors import ApiError
from app.modules.entities.identity import IDENTITY_POLICY, extract_entity_descriptors
from app.modules.ingestion.schemas import canonical_json
from app.modules.ueba import queries, views
from app.modules.ueba.schemas import UebaFilters

START = NOW.replace(hour=0) - timedelta(days=28)
OBSERVED = NOW.replace(hour=0)
END = OBSERVED + timedelta(days=1)


def fixture() -> dict[str, Any]:
    row = timeline_fixture()["items"][0]
    raw, normalized = row["raw"], row["normalized"]
    raw["envelope"]["raw_event"] = {"host": {"id": "host"}, "user": {"name": "alice"}}
    raw["payload_hash"] = hashlib.sha256(canonical_json(raw["envelope"])).hexdigest()
    raw["payload_bytes"] = len(canonical_json(raw["envelope"]))
    doc = normalized["document"]
    doc["raw_event"] = deepcopy(raw["envelope"]["raw_event"])
    doc["host"]["id"] = "host"
    doc["user"]["name"] = "alice"
    doc["raw_sha256"] = raw["payload_hash"]
    normalized["document_sha256"] = hashlib.sha256(canonical_json(doc)).hexdigest()
    descriptors = extract_entity_descriptors(doc)
    own = descriptors[0]
    row["receipt"] = {
        "event_id": raw["id"],
        "document_sha256": normalized["document_sha256"],
        "identity_policy": IDENTITY_POLICY,
        "observation_count": len(descriptors),
    }
    row["observations"] = [
        {
            "entity_id": str(d.entity_id),
            "event_id": raw["id"],
            "role": d.role,
            "timestamp": doc["timestamp"],
            "document_sha256": normalized["document_sha256"],
            "attributes": deepcopy(d.attributes),
        }
        for d in descriptors
    ]
    identity = {
        "id": str(own.entity_id),
        "kind": own.entity_type,
        "label": own.label,
        "identity_basis": own.identity_strength,
        "canonical_identity": own.canonical_key,
        "key_sha256": own.key_sha256,
        "identity_policy": IDENTITY_POLICY,
        "source_id": doc["source_id"],
        "mode": "live",
        "dataset_id": None,
        "run_id": str(UUID(int=0)),
    }
    return {
        "identity": identity,
        "event_count": 1,
        "pending": 0,
        "integrity_mismatch": False,
        "bytes": 1000,
        "items": [row],
        "as_of": NOW.isoformat(),
    }


def project(data: dict[str, Any]) -> Any:
    return views.project(data, UebaFilters(), START, OBSERVED, END)


def test_valid_original_and_all_roles_are_read_without_mutating_input() -> None:
    data = fixture()
    before = deepcopy(data)
    result = project(data)
    assert result.status == "cold_start" and result.observation.event_count == 1
    assert data == before


@pytest.mark.parametrize(
    "path,value",
    [
        (("identity", "key_sha256"), "a" * 64),
        (("identity", "identity_policy"), "wrong"),
        (("identity", "identity_basis"), "event_local"),
        (("identity", "source_id"), str(UUID(int=55))),
        (("identity", "run_id"), str(UUID(int=55))),
        (("identity", "dataset_id"), str(UUID(int=55))),
        (("identity", "canonical_identity", "value"), "other"),
        (("items", 0, "raw", "payload_hash"), "a" * 64),
        (("items", 0, "raw", "payload_bytes"), 1),
        (("items", 0, "raw", "source_id"), str(UUID(int=55))),
        (("items", 0, "normalized", "document_sha256"), "a" * 64),
        (("items", 0, "normalized", "document", "host", "id"), "other"),
        (("items", 0, "normalized", "timestamp"), "2026-10-04T00:00:00Z"),
        (("items", 0, "receipt", "event_id"), str(UUID(int=55))),
        (("items", 0, "receipt", "document_sha256"), "a" * 64),
        (("items", 0, "receipt", "identity_policy"), "wrong"),
        (("items", 0, "receipt", "observation_count"), 0),
        (("items", 0, "observations", 0, "role"), "target"),
        (("items", 0, "observations", 0, "event_id"), str(UUID(int=55))),
        (("items", 0, "observations", 0, "timestamp"), "2026-10-04T00:00:00Z"),
        (("items", 0, "observations", 0, "document_sha256"), "a" * 64),
        (("items", 0, "observations", 0, "attributes"), {}),
        (("items", 0, "observations", 1, "attributes"), {"user_name": "mallory"}),
        (("items", 0, "observations", 1, "entity_id"), str(UUID(int=55))),
        (("items", 0, "observations"), []),
        (("items",), []),
        (("integrity_mismatch",), True),
    ],
)
def test_proof_corruption_fails_closed(path: tuple[Any, ...], value: Any) -> None:
    data = fixture()
    node: Any = data
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value
    with pytest.raises(ApiError) as caught:
        project(data)
    assert caught.value.status == 409 and caught.value.code == "ueba_integrity_mismatch"


def test_duplicate_observed_role_cannot_hide_other_membership() -> None:
    data = fixture()
    row = data["items"][0]
    row["observations"].append(deepcopy(row["observations"][0]))
    with pytest.raises(ApiError, match="ueba_integrity_mismatch"):
        project(data)


@pytest.mark.parametrize("field,value", [("event_count", 2001), ("bytes", 8 * 1024 * 1024 + 1)])
def test_fixed_proof_bounds_reject_before_projection(field: str, value: int) -> None:
    assert queries.MAX_EVENTS == 2000 and queries.MAX_BYTES == 8 * 1024 * 1024
    data = fixture()
    data[field] = value
    data["items"] = [{"invalid": "must not be evaluated"}]
    with pytest.raises(ApiError) as caught:
        project(data)
    assert caught.value.code == "ueba_limit_exceeded"


def test_absent_scoped_identity_is_not_found() -> None:
    data = fixture()
    data["identity"] = None
    with pytest.raises(ApiError) as caught:
        project(data)
    assert caught.value.status == 404
