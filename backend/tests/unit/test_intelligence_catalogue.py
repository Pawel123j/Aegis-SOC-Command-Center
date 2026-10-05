"""Bounded metadata and exact IOC revision proof independent of persistence."""

import hashlib
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.modules.ingestion.schemas import canonical_json
from app.modules.intelligence.models import IOCIdentity, IOCRevision
from app.modules.intelligence.schemas import IOCFilters, IOCInput, IOCPatch, RevisionDocument
from app.modules.intelligence.service import ioc_view, normalized_input, revision_document


@pytest.mark.parametrize(
    "values",
    [
        {"source": " "},
        {"source": "bad\x00source"},
        {"source": "bad\ud800source"},
        {"source": "x" * 129},
        {"source": 12},
        {"confidence": True},
        {"confidence": -1},
        {"confidence": 101},
        {"confidence": "90"},
        {"confidence": 1.5},
        {"active": "true"},
        {"tags": ["same", "same"]},
        {"tags": [" "]},
        {"tags": ["x" * 65]},
        {"tags": ["bad\n"]},
        {"tags": ["bad\udfff"]},
        {"tags": [1]},
        {"tags": [str(i) for i in range(17)]},
        {"description": "x" * 2049},
        {"description": "bad\x01description"},
        {"description": "bad\ud800"},
        {"first_seen": "2026-10-01T00:00:00"},
        {"first_seen": "2026-10-02T00:00:00Z", "last_seen": "2026-10-01T00:00:00Z"},
        {"type": "email"},
        {"value": False},
        {"unknown": "ignored"},
    ],
)
def test_metadata_rejects_invalid_fields_without_echoing_input(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError) as rejected:
        IOCInput.model_validate(
            {"type": "domain", "value": "example.test", "source": "local", **values}
        )
    assert "input_value=" not in str(rejected.value)


@pytest.mark.parametrize(
    "values",
    [
        {},
        {"source": None},
        {"active": None},
        {"reputation": None},
        {"description": None},
        {"tags": None},
        {"type": "ip"},
        {"value": "192.0.2.1"},
        {"id": str(uuid4())},
    ],
)
def test_patch_cannot_change_identity_or_clear_required_fields(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        IOCPatch.model_validate(values)


def test_optional_metadata_can_be_cleared_and_times_normalized() -> None:
    patch = IOCPatch(confidence=None, first_seen=None, last_seen=None)
    assert patch.model_dump(exclude_unset=True) == {
        "confidence": None,
        "first_seen": None,
        "last_seen": None,
    }
    data = IOCInput(
        type="domain",
        value="EXAMPLE.TEST.",
        source=" local ",
        first_seen=datetime.fromisoformat("2026-10-01T12:00:00+02:00"),
        description="Multiline\ntext\tallowed",
        tags=[" Review "],
    )
    normalized = normalized_input(data)
    assert normalized.value == "example.test"
    assert normalized.source == "local" and normalized.tags == ["Review"]
    assert normalized.first_seen == datetime(2026, 10, 1, 10, tzinfo=UTC)


def revision() -> tuple[IOCIdentity, IOCRevision]:
    identity, identifier, actor = uuid4(), uuid4(), uuid4()
    document = RevisionDocument(
        type="domain",
        value="example.test",
        canonical_value="example.test",
        source="Local analyst declaration",
        tags=["review"],
        ioc_id=identity,
        revision_id=identifier,
        revision=1,
    ).model_dump(mode="json")
    canonical = canonical_json(document)
    moment = datetime(2026, 10, 5, tzinfo=UTC)
    ioc = IOCIdentity(
        id=identity,
        kind="domain",
        canonical_value="example.test",
        normalization_version="ioc-normalization-v1",
        version=1,
        current_revision_id=identifier,
        created_by=actor,
        created_at=moment,
    )
    row = IOCRevision(
        id=identifier,
        ioc_id=identity,
        revision=1,
        document=document,
        canonical_document=canonical.decode(),
        document_sha256=hashlib.sha256(canonical).hexdigest(),
        created_by=actor,
        created_at=moment,
    )
    return ioc, row


def test_document_and_view_verify_immutable_proof_and_do_not_alias_tags() -> None:
    identity, row = revision()
    original = deepcopy(row.document)
    result = revision_document(row)
    result["tags"].append("changed by caller")
    assert row.document == original
    view = ioc_view(identity, row)
    assert view.id == identity.id and view.version == view.revision == 1
    assert view.confidence is None and view.reputation == "unknown"


@pytest.mark.parametrize(
    "change",
    [
        "hash",
        "canonical",
        "ioc_id",
        "revision_id",
        "revision",
        "normalization",
        "notcanonical",
        "extra",
        "confidence",
        "source",
    ],
)
def test_revision_proof_fails_closed_even_after_consistent_rehash(change: str) -> None:
    _, row = revision()
    if change == "hash":
        row.document_sha256 = "0" * 64
    elif change == "canonical":
        row.canonical_document = "{}"
    else:
        fields = {
            "ioc_id": "ioc_id",
            "revision_id": "revision_id",
            "revision": "revision",
            "normalization": "normalization_version",
            "notcanonical": "value",
            "extra": "unknown",
            "confidence": "confidence",
            "source": "source",
        }
        values = {
            "ioc_id": str(uuid4()),
            "revision_id": str(uuid4()),
            "revision": 2,
            "normalization": "other-v1",
            "notcanonical": "EXAMPLE.TEST.",
            "extra": "unreviewed",
            "confidence": True,
            "source": "bad\ud800",
        }
        row.document[fields[change]] = values[change]
        # Surrogates are rejected before a UTF-8 canonical document can be made.
        if change != "source":
            canonical = canonical_json(row.document)
            row.canonical_document = canonical.decode()
            row.document_sha256 = hashlib.sha256(canonical).hexdigest()
    with pytest.raises(ValueError, match="intelligence_revision_integrity_mismatch"):
        revision_document(row)


@pytest.mark.parametrize(
    "values",
    [
        {"limit": 0},
        {"limit": 101},
        {"q": " "},
        {"q": "x\x00y"},
        {"q": "x" * 129},
        {"kind": "email"},
        {"reputation": "good"},
        {"cursor": "x" * 4097},
        {"extra": "hidden"},
    ],
)
def test_catalogue_filters_remain_bounded_and_explicit(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        IOCFilters.model_validate(values)
