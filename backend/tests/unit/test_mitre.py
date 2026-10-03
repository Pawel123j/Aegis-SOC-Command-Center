"""Offline pinned identities, explicit candidate associations and scope boundaries."""

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.modules.correlation.builtin import BUILTIN_RULES as CORRELATION_RULES
from app.modules.detections.builtin import BUILTIN_RULES
from app.modules.mitre.catalogue import (
    CATALOGUE_PATH,
    CATALOGUE_SHA256,
    catalogue,
    catalogue_view,
    read_catalogue,
    validate_document,
)
from app.modules.mitre.mapping import associate, legacy_mapping, rule_mapping, validate_pair
from app.modules.mitre.schemas import CoverageFilters


def document() -> dict[str, Any]:
    return json.loads(CATALOGUE_PATH.read_bytes())  # type: ignore[no-any-return]


def test_pinned_catalogue_includes_exact_active_and_historical_release() -> None:
    data = catalogue()
    assert hashlib.sha256(CATALOGUE_PATH.read_bytes()).hexdigest() == CATALOGUE_SHA256
    assert len(data.tactics) == 15 and len(data.techniques) == 858
    assert sum(item.active for item in data.techniques) == 697
    assert sum(item.revoked for item in data.techniques) == 149
    assert sum(item.deprecated for item in data.techniques) == 12
    assert data.tactic("TA0005").name == "Stealth"
    assert data.tactic("TA0112").name == "Defense Impairment"
    assert data.technique("T1059.001").parent_id == "T1059"
    assert data.technique("T1059.001").tactic_ids == ("TA0002",)
    view = catalogue_view()
    assert len(view.techniques) == view.catalogue.techniques_count == 697
    assert view.catalogue.source_commit in view.catalogue.source_url
    assert "MITRE Corporation" in view.catalogue.attribution


def test_cached_catalogue_is_deeply_immutable_and_api_values_are_fresh() -> None:
    data = catalogue()
    with pytest.raises(ValidationError):
        data.techniques[0].name = "tampered"
    with pytest.raises(AttributeError):
        data.techniques[0].tactic_ids.append("TA9999")  # type: ignore[attr-defined]
    first = catalogue_view()
    first.techniques[0].name = "tampered"
    first.techniques[0].tactic_ids.append("TA9999")
    second = catalogue_view()
    assert second.techniques[0].name != "tampered"
    assert "TA9999" not in second.techniques[0].tactic_ids


def test_catalogue_rejects_modified_file_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / "catalogue.json"
    path.write_bytes(CATALOGUE_PATH.read_bytes().replace(b"PowerShell", b"Powershell", 1))
    with pytest.raises(ValueError, match="integrity"):
        read_catalogue(path)


@pytest.mark.parametrize(
    "change",
    [
        "duplicate_technique",
        "duplicate_tactic",
        "unknown_tactic",
        "duplicate_relation",
        "active_missing_parent",
        "incorrect_parent",
        "incorrect_subtechnique_flag",
        "unsafe_url",
        "retired_tactic",
        "unknown_key",
        "source_commit",
        "source_url",
        "empty_tactics",
    ],
)
def test_catalogue_rejects_invalid_identities_relationships_and_provenance(change: str) -> None:
    value = document()
    technique = next(item for item in value["techniques"] if item["id"] == "T1059.001")
    if change == "duplicate_technique":
        value["techniques"].append(deepcopy(technique))
    elif change == "duplicate_tactic":
        value["tactics"].append(deepcopy(value["tactics"][0]))
    elif change == "unknown_tactic":
        technique["tactic_ids"] = ["TA9999"]
    elif change == "duplicate_relation":
        technique["tactic_ids"] *= 2
    elif change == "active_missing_parent":
        technique["parent_id"] = None
    elif change == "incorrect_parent":
        technique["parent_id"] = "T1078"
    elif change == "incorrect_subtechnique_flag":
        technique["is_subtechnique"] = False
    elif change == "unsafe_url":
        technique["url"] = "javascript:alert(1)"
    elif change == "retired_tactic":
        next(item for item in value["tactics"] if item["id"] == "TA0002")["revoked"] = True
    elif change == "unknown_key":
        technique["command"] = "untrusted"
    elif change == "source_commit":
        value["provenance"]["source_commit"] = "0" * 40
    elif change == "source_url":
        value["provenance"]["source_url"] = "https://example.com/catalogue.json"
    else:
        technique["tactic_ids"] = []
    with pytest.raises(ValueError):
        validate_document(value)


def test_historical_missing_parent_is_not_invented() -> None:
    historical = [
        item for item in catalogue().techniques if item.is_subtechnique and item.parent_id is None
    ]
    assert len(historical) == 16 and all(not item.active for item in historical)


@pytest.mark.parametrize("identity", ["T9999", "T1059.999", "TA0002", "T1059.001 OR 1=1"])
def test_unknown_techniques_fail_closed(identity: str) -> None:
    with pytest.raises(ValueError):
        associate([identity])


def test_retired_techniques_and_wrong_tactic_pair_fail_closed() -> None:
    retired = next(item.id for item in catalogue().techniques if not item.active)
    with pytest.raises(ValueError):
        associate([retired])
    with pytest.raises(ValueError):
        validate_pair("T1059.001", "TA0003")
    validate_pair("T1059.001", "TA0002")
    with pytest.raises(ValueError):
        associate(["T1059.001", "T1059.001"])


@pytest.mark.parametrize("rule", [*BUILTIN_RULES, *CORRELATION_RULES])
def test_mapping_is_separate_from_frozen_rule_and_never_claims_confirmed_attack(rule: Any) -> None:
    original = rule.snapshot()
    view = rule_mapping(rule.id)
    assert view.claim == "candidate_association" and view.confirmed_attack is False
    assert [item.id for item in view.techniques] == sorted(rule.mitre)
    assert rule.snapshot() == original
    assert "mitre_mapping" not in original
    if rule.id == "linux-root-session":
        assert view.status == "unmapped" and view.techniques == []
    else:
        assert view.status == "mapped"
    view.techniques.clear()
    assert rule_mapping(rule.id).techniques or rule.id == "linux-root-session"


def test_all_official_tactic_associations_are_references_without_extra_parent_count() -> None:
    powershell = associate(["T1059.001"])
    assert len(powershell) == 1
    assert [item.id for item in powershell[0].tactics] == ["TA0002"]
    valid_account = associate(["T1078"])[0]
    assert [item.id for item in valid_account.tactics] == ["TA0001", "TA0003", "TA0004", "TA0005"]
    assert legacy_mapping().catalogue_hash is None


@pytest.mark.parametrize(
    "data",
    [
        {"mode": "replay"},
        {"mode": "replay", "dataset_id": uuid4()},
        {"mode": "replay", "dataset_id": uuid4(), "run_id": UUID(int=0)},
        {"mode": "live", "dataset_id": uuid4()},
        {"mode": "live", "run_id": uuid4()},
        {"from": "2026-01-01T00:00:00"},
        {"to": "2026-01-01T01:00:00+01:00"},
        {"unexpected": "ignored"},
    ],
)
def test_coverage_filters_reject_ambiguous_scope_and_non_utc_time(data: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        CoverageFilters.model_validate(data)


@pytest.mark.parametrize("offset", [-1, 0, 367])
def test_coverage_window_rejects_nonpositive_or_oversized_ranges(offset: int) -> None:
    now = datetime(2026, 10, 3, tzinfo=UTC)
    filters = CoverageFilters(from_=now - timedelta(days=offset), to=now)
    with pytest.raises(ValueError):
        filters.window(now)


def test_coverage_window_defaults_and_future_guard() -> None:
    now = datetime(2026, 10, 3, tzinfo=UTC)
    assert CoverageFilters().window(now) == (now - timedelta(days=30), now)
    assert CoverageFilters(from_=now - timedelta(days=366), to=now).window(now)[0]
    with pytest.raises(ValueError):
        CoverageFilters(to=now + timedelta(microseconds=1)).window(now)
