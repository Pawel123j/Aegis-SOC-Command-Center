"""Conservative identity policy rejects accidental joins and preserves source assertions."""

import hashlib
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.modules.entities.identity import (
    IDENTITY_POLICY,
    MAX_ENTITY_DESCRIPTORS,
    EntityDescriptor,
    extract_entity_descriptors,
)
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.schemas import NormalizedSecurityEvent


def document(**values: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "event_id": str(UUID(int=1)),
        "source_id": str(UUID(int=2)),
        "dataset_id": str(UUID(int=3)),
        "run_id": str(UUID(int=0)),
        "mode": "live",
        "timestamp": "2026-10-04T08:00:00Z",
        "received_at": "2026-10-04T08:00:01Z",
        "processed_at": "2026-10-04T08:00:02Z",
        "source": {"name": "Observed source", "type": "generic_json"},
        "host": {"id": "host-opaque-1", "name": "SERVER-1"},
        "user": {},
        "process": {},
        "event": {"category": "process", "action": "start"},
        "raw_event": {},
        "raw_sha256": "ab" * 32,
    }
    result.update(values)
    return result


def by_role(result: tuple[EntityDescriptor, ...], role: str) -> EntityDescriptor:
    return next(item for item in result if item.role == role)


def descriptor(role: str, **values: Any) -> EntityDescriptor:
    return by_role(extract_entity_descriptors(document(**values)), role)


def test_no_missing_or_synthetic_entities() -> None:
    assert extract_entity_descriptors(document(host={})) == ()
    assert (
        extract_entity_descriptors(
            document(host={"id": "-", "name": " "}, user={"id": "-", "name": " "})
        )
        == ()
    )


def test_all_roles_are_bounded_and_distinct_observations() -> None:
    result = extract_entity_descriptors(
        document(
            source={"name": "Windows", "type": "windows_process", "ip": "192.0.2.1"},
            destination={"ip": "192.0.2.1"},
            user={"name": "Administrator", "target": {"name": "ADMINISTRATOR"}},
            process={"entity_id": "child", "parent_entity_id": "parent", "pid": 1, "parent_pid": 2},
        )
    )
    assert len(result) == 7 < MAX_ENTITY_DESCRIPTORS
    assert {item.role for item in result} == {
        "host",
        "actor",
        "target",
        "source",
        "destination",
        "process",
        "parent",
    }
    assert by_role(result, "actor").entity_id == by_role(result, "target").entity_id
    assert by_role(result, "source").entity_id == by_role(result, "destination").entity_id
    assert all(item.timestamp == datetime(2026, 10, 4, 8, tzinfo=UTC) for item in result)
    assert all(item.policy_version == IDENTITY_POLICY for item in result)


@pytest.mark.parametrize(
    "role,values",
    [
        ("host", {}),
        ("actor", {"user": {"name": "alice"}}),
        ("process", {"process": {"entity_id": "instance"}}),
    ],
)
def test_identity_is_source_scoped(role: str, values: dict[str, Any]) -> None:
    assert (
        descriptor(role, **values).entity_id
        != descriptor(
            role,
            source_id=str(UUID(int=99)),
            **values,
        ).entity_id
    )


def test_live_scope_intentionally_ignores_dataset_and_event_ids() -> None:
    before = descriptor("host")
    after = descriptor("host", dataset_id=str(UUID(int=999)), event_id=str(UUID(int=98)))
    assert before.entity_id == after.entity_id
    assert before.canonical_key["dataset_id"] == ""
    assert before.canonical_key["mode"] == "live"


@pytest.mark.parametrize("field", ["dataset_id", "run_id"])
def test_replay_dataset_and_run_are_exact_identity_namespaces(field: str) -> None:
    values = {"mode": "replay", "run_id": str(UUID(int=4))}
    base = descriptor("host", **values)
    assert base.entity_id != descriptor("host").entity_id
    values[field] = str(UUID(int=99))
    assert base.entity_id != descriptor("host", **values).entity_id


@pytest.mark.parametrize(
    "values",
    [
        {"mode": "live", "run_id": str(UUID(int=4))},
        {"mode": "replay", "run_id": str(UUID(int=0))},
        {"mode": "replay", "run_id": str(UUID(int=4)), "dataset_id": str(UUID(int=0))},
    ],
)
def test_impossible_scope_is_rejected(values: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="entity scope"):
        extract_entity_descriptors(document(**values))


def test_opaque_host_ids_preserve_case_and_do_not_alias_names() -> None:
    before = descriptor("host", host={"id": "OpaqueID", "name": "SERVER-1"})
    after = descriptor("host", host={"id": "opaqueid", "name": "SERVER-1"})
    assert before.entity_id != after.entity_id
    assert before.entity_id != descriptor("host", host={"name": "OpaqueID"}).entity_id
    assert before.label == "OpaqueID"
    assert before.attributes["host_name"] == "SERVER-1"


def test_host_names_follow_dns_case_and_trailing_root_policy() -> None:
    assert (
        descriptor("host", host={"name": "SERVER.Example.COM."}).entity_id
        == descriptor(
            "host",
            host={"name": "server.example.com"},
        ).entity_id
    )


def test_opaque_linux_host_name_case_is_preserved() -> None:
    assert (
        descriptor("host", host={"name": "HOST_one"}).entity_id
        != descriptor(
            "host",
            host={"name": "host_one"},
        ).entity_id
    )


def test_opaque_windows_host_name_case_is_folded() -> None:
    values = {"source": {"type": "windows_auth", "name": "Windows"}}
    assert (
        descriptor("host", host={"name": "HOST_one"}, **values).entity_id
        == descriptor(
            "host",
            host={"name": "host_one"},
            **values,
        ).entity_id
    )


@pytest.mark.parametrize("source_type", ["windows_auth", "windows_process"])
def test_windows_names_and_realms_fold_case_without_aliasing_sid(source_type: str) -> None:
    values = {"source": {"type": source_type, "name": "Windows"}}
    upper = descriptor("actor", user={"name": "Administrator", "realm": "DOMAIN"}, **values)
    lower = descriptor("actor", user={"name": "administrator", "realm": "domain"}, **values)
    sid = descriptor(
        "actor",
        user={
            "id": "S-1-5-21-1-2-3-500",
            "name": "Administrator",
            "realm": "DOMAIN",
        },
        **values,
    )
    assert upper.entity_id == lower.entity_id
    assert upper.entity_id != sid.entity_id
    assert upper.identity_strength == "host_scoped"
    assert sid.identity_strength == "source_scoped"


def test_linux_names_and_realms_are_case_sensitive() -> None:
    assert (
        descriptor("actor", user={"name": "Admin", "realm": "local"}).entity_id
        != descriptor(
            "actor",
            user={"name": "admin", "realm": "local"},
        ).entity_id
    )
    assert (
        descriptor("actor", user={"name": "admin", "realm": "LOCAL"}).entity_id
        != descriptor(
            "actor",
            user={"name": "admin", "realm": "local"},
        ).entity_id
    )


def test_windows_and_case_sensitive_account_names_use_separate_namespaces() -> None:
    values = {"user": {"name": "admin"}}
    assert (
        descriptor("actor", **values).entity_id
        != descriptor(
            "actor",
            host={"id": "host-opaque-1", "os": "Windows"},
            **values,
        ).entity_id
    )


@pytest.mark.parametrize(
    "user",
    [
        {"name": "alice"},
        {"id": "1000"},
        {"id": "0", "name": "root"},
    ],
)
def test_names_and_uid_are_host_scoped(user: dict[str, str]) -> None:
    before = descriptor("actor", user=user)
    assert before.identity_strength == "host_scoped"
    assert before.entity_id != descriptor("actor", user=user, host={"id": "other-host"}).entity_id


def test_linux_root_uid_zero_is_valid_while_windows_zero_is_not_sid() -> None:
    assert descriptor("actor", user={"id": "0"}).canonical_key["value"] == "0"
    assert not any(
        item.role == "actor"
        for item in extract_entity_descriptors(
            document(
                source={"type": "windows_auth", "name": "Windows"},
                user={"id": "0"},
            )
        )
    )


@pytest.mark.parametrize("user", [{"name": "alice"}, {"id": "1000"}])
def test_missing_host_makes_weak_accounts_event_local(user: dict[str, str]) -> None:
    before = descriptor("actor", host={}, user=user)
    after = descriptor("actor", host={}, user=user, event_id=str(UUID(int=50)))
    assert before.identity_strength == "event_local"
    assert before.entity_id != after.entity_id


@pytest.mark.parametrize("sid", ["S-1-5-21-1-2-3-500", "S-1-12-1-1-2-3-4"])
def test_complete_account_sid_is_source_scoped_without_observed_host(sid: str) -> None:
    values = {"source": {"type": "windows_auth", "name": "Windows"}, "user": {"id": sid}}
    before = descriptor("actor", host={}, **values)
    assert before.identity_strength == "source_scoped"
    assert (
        before.entity_id == descriptor("actor", host={"id": "different-host"}, **values).entity_id
    )
    assert (
        before.entity_id
        != descriptor("actor", source_id=str(UUID(int=44)), host={}, **values).entity_id
    )


@pytest.mark.parametrize("sid", ["S-1-5-18", "S-1-5-32-544", "S-1-5-21-1-2-3"])
def test_well_known_and_domain_sid_do_not_merge_hosts(sid: str) -> None:
    values = {"source": {"type": "windows_auth", "name": "Windows"}, "user": {"id": sid}}
    before = descriptor("actor", **values)
    assert before.identity_strength == "host_scoped"
    assert (
        before.entity_id != descriptor("actor", host={"id": "different-host"}, **values).entity_id
    )
    missing = descriptor("actor", host={}, **values)
    assert missing.identity_strength == "event_local"
    assert (
        missing.entity_id
        != descriptor("actor", host={}, event_id=str(UUID(int=44)), **values).entity_id
    )


@pytest.mark.parametrize(
    "sid",
    [
        "-",
        "0",
        "0x0",
        "S-1-0-0",
        "S-2-5-18",
        "S-1-5",
        "s-1-5-18",
        " S-1-5-18",
        "S-1-5-18x",
        "S-1-281474976710656-1",
        "S-1-5-4294967296",
        "S-1-5" + "-1" * 16,
        "S-1-５-18",
        "S-1-5-+18",
        "S-1-5--18",
    ],
)
def test_invalid_or_placeholder_sid_does_not_become_identity(sid: str) -> None:
    values = {"source": {"type": "windows_auth", "name": "Windows"}, "user": {"id": sid}}
    assert not any(item.role == "actor" for item in extract_entity_descriptors(document(**values)))
    values["user"]["name"] = "fallback-name"
    assert descriptor("actor", **values).canonical_key["basis"] == "account_name"


def test_sid_canonical_numeric_notation_has_stable_key() -> None:
    values = {"source": {"type": "windows_auth", "name": "Windows"}}
    assert (
        descriptor("actor", user={"id": "S-1-005-021-01-02-03-00500"}, **values).entity_id
        == descriptor(
            "actor",
            user={"id": "S-1-5-21-1-2-3-500"},
            **values,
        ).entity_id
    )


def test_account_alias_changes_do_not_change_sid_identity_or_label() -> None:
    values = {"source": {"type": "windows_auth", "name": "Windows"}}
    before = descriptor("actor", user={"id": "S-1-5-21-1-2-3-500", "name": "old"}, **values)
    after = descriptor("actor", user={"id": "S-1-5-21-1-2-3-500", "name": "renamed"}, **values)
    assert before.entity_id == after.entity_id
    assert before.label == after.label == "S-1-5-21-1-2-3-500"
    assert before.attributes != after.attributes


def test_ip_is_global_within_scope_and_roles_share_identity() -> None:
    before = descriptor("source", source={"name": "First", "type": "nginx", "ip": "192.0.2.1"})
    after = descriptor(
        "source",
        source_id=str(UUID(int=99)),
        source={
            "name": "Second",
            "type": "firewall",
            "ip": "192.0.2.1",
        },
    )
    assert before.entity_id == after.entity_id
    assert "source_id" not in before.canonical_key
    assert before.identity_strength == "network_address"


def test_ip_is_isolated_from_other_addresses_and_replay_namespaces() -> None:
    values = {"source": {"name": "Network", "type": "firewall", "ip": "192.0.2.1"}}
    before = descriptor("source", **values)
    assert (
        before.entity_id
        != descriptor("source", mode="replay", run_id=str(UUID(int=4)), **values).entity_id
    )
    assert (
        before.entity_id
        != descriptor(
            "source",
            source={
                "name": "Network",
                "type": "firewall",
                "ip": "192.0.2.2",
            },
        ).entity_id
    )


def test_ipv6_canonicalization_preserves_mapped_ipv6_contract() -> None:
    def address(value: str) -> EntityDescriptor:
        return descriptor("source", source={"name": "IP", "type": "nginx", "ip": value})

    assert (
        address("2001:0db8:0000:0000:0000:0000:0000:0001").entity_id
        == address("2001:db8::1").entity_id
    )
    mapped = address("::ffff:192.0.2.1")
    assert mapped.canonical_key["value"] == "::ffff:c000:201"
    assert mapped.entity_id != address("192.0.2.1").entity_id
    assert mapped.entity_id == address("::FFFF:C000:0201").entity_id


def test_process_entity_id_is_host_scoped_and_ignores_name_aliases() -> None:
    before = descriptor(
        "process", process={"entity_id": "instance-opaque", "name": "old.exe", "pid": 5}
    )
    after = descriptor(
        "process", process={"entity_id": "instance-opaque", "name": "new.exe", "pid": 10}
    )
    assert before.identity_strength == "host_scoped"
    assert before.entity_id == after.entity_id
    assert before.label == after.label == "instance-opaque"
    assert (
        before.entity_id
        != descriptor(
            "process",
            host={"id": "other"},
            process={
                "entity_id": "instance-opaque",
            },
        ).entity_id
    )


@pytest.mark.parametrize(
    "process",
    [
        {"pid": 10},
        {"pid": 0},
        {"name": "same.exe"},
        {"executable": "C:\\same.exe"},
        {"hash": "sha256:abc"},
        {"entity_id": "strong-but-no-host"},
    ],
)
def test_bare_pid_name_and_missing_host_never_merge_process_instances(
    process: dict[str, Any],
) -> None:
    values = {"process": process}
    if "entity_id" in process:
        values["host"] = {}
    before = descriptor("process", **values)
    assert before.identity_strength == "event_local"
    assert before.entity_id != descriptor("process", event_id=str(UUID(int=50)), **values).entity_id


def test_parent_process_never_borrows_child_name_executable_or_hash() -> None:
    result = extract_entity_descriptors(
        document(
            process={
                "entity_id": "child",
                "name": "child.exe",
                "executable": "C:\\child.exe",
                "hash": "child-hash",
                "pid": 1,
                "parent_entity_id": "parent",
                "parent_pid": 2,
            }
        )
    )
    parent = by_role(result, "parent")
    assert parent.attributes == {"entity_id": "parent", "pid": 2}
    assert parent.entity_id != by_role(result, "process").entity_id


def test_weak_parent_and_child_roles_do_not_claim_same_instance_from_reused_pid() -> None:
    result = extract_entity_descriptors(document(process={"pid": 100, "parent_pid": 100}))
    assert by_role(result, "parent").entity_id != by_role(result, "process").entity_id
    assert by_role(result, "parent").identity_strength == "event_local"


def test_same_strong_process_reference_may_have_two_distinct_roles() -> None:
    result = extract_entity_descriptors(
        document(process={"entity_id": "same", "parent_entity_id": "same"})
    )
    assert by_role(result, "parent").entity_id == by_role(result, "process").entity_id


def test_windows_guid_case_and_braces_are_canonical_but_other_opaque_ids_are_exact() -> None:
    identifier = "abababab-1234-4321-1111-121212121212"
    values = {"source": {"name": "Windows", "type": "windows_process"}}
    assert (
        descriptor(
            "process", process={"entity_id": "{" + identifier.upper() + "}"}, **values
        ).entity_id
        == descriptor(
            "process",
            process={"entity_id": identifier},
            **values,
        ).entity_id
    )
    assert (
        descriptor("process", process={"entity_id": identifier.upper()}).entity_id
        != descriptor(
            "process",
            process={"entity_id": identifier},
        ).entity_id
    )
    assert (
        descriptor("process", process={"entity_id": "OPAQUE"}, **values).entity_id
        != descriptor(
            "process",
            process={"entity_id": "opaque"},
            **values,
        ).entity_id
    )


@pytest.mark.parametrize("identifier", ["-", "0", "0x0", str(UUID(int=0))])
def test_process_placeholder_does_not_create_strong_identity(identifier: str) -> None:
    result = extract_entity_descriptors(document(process={"entity_id": identifier}))
    assert not any(item.role == "process" for item in result)
    fallback = descriptor("process", process={"entity_id": identifier, "pid": 10})
    assert fallback.identity_strength == "event_local"


def test_identity_hash_is_canonical_and_input_is_not_mutated() -> None:
    original = document(user={"name": "alice"}, process={"entity_id": "instance"})
    saved = deepcopy(original)
    before = extract_entity_descriptors(original)
    reordered = dict(reversed(list(original.items())))
    reordered["host"] = dict(reversed(list(original["host"].items())))
    after = extract_entity_descriptors(reordered)
    assert original == saved
    assert before == after
    for item in before:
        assert item.key_sha256 == hashlib.sha256(canonical_json(item.canonical_key)).hexdigest()
        assert item.canonical_key["policy"] == IDENTITY_POLICY
        assert item.canonical_key["kind"] == item.entity_type
        assert len(canonical_json(item.canonical_key)) <= 8192
    model = NormalizedSecurityEvent.model_validate(original)
    assert extract_entity_descriptors(model) == before


def test_roles_own_independent_dictionary_copies() -> None:
    result = extract_entity_descriptors(
        document(user={"name": "alice", "target": {"name": "alice"}})
    )
    actor, target = by_role(result, "actor"), by_role(result, "target")
    assert actor.canonical_key == target.canonical_key
    actor.canonical_key["value"] = "caller-changed"
    actor.attributes["user_name"] = "caller-changed"
    assert target.canonical_key["value"] == "alice"
    assert target.attributes["user_name"] == "alice"


def test_nonidentity_event_fields_do_not_change_stable_id() -> None:
    before = descriptor("host")
    after = descriptor("host", timestamp="2026-10-04T09:00:00Z", raw_event={"different": "data"})
    assert before.entity_id == after.entity_id
    assert before.timestamp != after.timestamp


def test_bounds_preserve_original_identity_and_limit_only_display_label() -> None:
    executable = "e" * 1024
    result = descriptor("process", process={"executable": executable})
    assert result.label == "e" * 256
    assert result.attributes["executable"] == executable
    assert len(canonical_json(result.attributes)) < 8192


@pytest.mark.parametrize(
    "values",
    [
        {"host": {"name": "x" * 257}},
        {"user": {"name": "null\x00"}},
        {"source": {"name": "Bad", "type": "nginx", "ip": "not-an-ip"}},
        {"process": {"pid": True}},
        {"timestamp": "2026-10-04T08:00:00"},
        {"inventory_verified": True},
    ],
)
def test_unvalidated_or_hostile_documents_are_rejected(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        extract_entity_descriptors(document(**values))
