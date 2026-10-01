"""Golden source facts and hostile inputs for every supported adapter."""

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.modules.normalization.parsers import NormalizationContext, NormalizationError, normalize
from app.modules.normalization.schemas import NormalizedSecurityEvent

CONTEXT = NormalizationContext(
    event_id=UUID(int=1),
    source_id=UUID(int=2),
    dataset_id=UUID(int=3),
    run_id=UUID(int=0),
    source_event_id="original-42",
    mode="live",
    source_name="trusted source",
    source_type="generic_json",
    timezone="UTC",
    received_at=datetime(2026, 1, 1, tzinfo=UTC),
    processed_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC),
    raw_sha256="ab" * 32,
)
GOLDEN = json.loads(
    (Path(__file__).parents[1] / "fixtures/normalization/golden.json").read_text("utf-8")
)


def event(raw: Any, source_type: str = "generic_json", **envelope: Any) -> NormalizedSecurityEvent:
    return normalize(
        {"source_type": source_type, "raw_event": raw, **envelope},
        replace(CONTEXT, source_type=source_type),
    )


@pytest.mark.parametrize("fixture", GOLDEN, ids=lambda fixture: fixture["name"])
def test_golden_adapter_facts(fixture: dict[str, Any]) -> None:
    result = event(fixture["raw_event"], fixture["source_type"]).model_dump(mode="json")
    for path, expected in fixture["expected"].items():
        actual: Any = result
        for segment in path.split("."):
            actual = actual[segment]
        assert actual == expected, path
    assert result["schema_version"] == "1.0"
    assert result["parser_version"] == "1.0.0"
    assert result["event_id"] == str(CONTEXT.event_id)
    assert result["source_id"] == str(CONTEXT.source_id)
    assert result["dataset_id"] == str(CONTEXT.dataset_id)
    assert result["run_id"] == str(CONTEXT.run_id)
    assert result["source_event_id"] == CONTEXT.source_event_id
    assert result["source"]["name"] == CONTEXT.source_name
    assert result["source"]["type"] == fixture["source_type"]
    assert result["raw_event"] == fixture["raw_event"]
    assert result["raw_sha256"] == CONTEXT.raw_sha256
    assert result["received_at"] == "2026-01-01T00:00:00Z"
    assert result["processed_at"] == "2026-01-01T00:00:01Z"
    assert set(result) == {
        "schema_version",
        "parser_version",
        "event_id",
        "source_id",
        "dataset_id",
        "run_id",
        "source_event_id",
        "mode",
        "timestamp",
        "received_at",
        "processed_at",
        "source",
        "destination",
        "host",
        "user",
        "session",
        "process",
        "event",
        "network",
        "http",
        "file",
        "raw_event",
        "raw_sha256",
        "extensions",
        "quality",
    }


def test_scope_is_server_owned_and_raw_is_preserved() -> None:
    raw = {
        "event_id": "attacker",
        "mode": "replay",
        "dataset_id": "attacker",
        "received_at": "1970-01-01T00:00:00Z",
        "parser_version": "evil",
        "source": {"name": "attacker", "type": "windows_auth", "ip": "192.0.2.1"},
        "quality": ["invented"],
        "risk": 100,
        "role": "admin",
    }
    result = event(raw)
    assert result.event_id == CONTEXT.event_id
    assert result.mode == "live"
    assert result.received_at == CONTEXT.received_at
    assert result.source.name == CONTEXT.source_name
    assert result.source.type == "generic_json"
    assert result.raw_event == raw
    assert "scope_fields_ignored" in result.quality
    assert not hasattr(result, "risk")


def test_absent_time_uses_observation_with_explicit_quality() -> None:
    result = event({"message": "unknown but retained"})
    assert result.timestamp == CONTEXT.received_at
    assert result.quality == ["timestamp_from_received_at", "missing_source_timestamp"]
    assert result.user.name is None
    assert result.source.ip is None
    assert result.process.pid is None
    assert result.event.outcome == "unknown"


def test_time_priority_envelope_raw_format() -> None:
    raw = {
        "timestamp": "2026-01-01T02:00:00+01:00",
        "message": (
            "Dec 31 23:59:59 host sshd[1]: Accepted password for alice from 192.0.2.1 port 22 ssh2"
        ),
    }
    result = event(raw, "linux_auth", timestamp="2026-01-01T03:00:00+01:00")
    assert result.timestamp == datetime(2026, 1, 1, 2, tzinfo=UTC)
    assert "inferred_year" not in result.quality
    assert event(raw, "linux_auth").timestamp == datetime(2026, 1, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "value", ["2026-01-01", "2026-01-01T01:00:00", "bad", 123, "2026-02-30T00:00:00Z"]
)
def test_invalid_source_timestamp_never_falls_back(value: object) -> None:
    with pytest.raises(NormalizationError) as error:
        event({"timestamp": value})
    assert error.value.code == "invalid_timestamp"


def test_json_string_preserves_text_and_uses_inner_time() -> None:
    raw = '{ "timestamp":"2026-01-01T01:00:00+01:00", "username": "alice" }'
    result = event(raw)
    assert result.raw_event == raw
    assert result.timestamp == CONTEXT.received_at
    assert result.user.name == "alice"


@pytest.mark.parametrize("raw", ['{"a":1,"a":2}', '{"a":NaN}', "[]", "{bad}"])
def test_json_text_shape_and_duplicate_keys(raw: str) -> None:
    with pytest.raises(NormalizationError):
        event(raw)


@pytest.mark.parametrize(
    "raw",
    [
        {"source_ip": "999.1.1.1"},
        {"source_ip": 1},
        {"source_port": -1},
        {"source_port": 65536},
        {"source_port": True},
        {"source_port": "22"},
        {"process": {"pid": -1}},
        {"process": {"pid": 4294967296}},
        {"username": "x" * 257},
        {"event": {"severity": "dangerous"}},
        {"result": "maybe"},
        {"user": {"target": {"unexpected": "value"}}},
        {"http": {"status_code": 999}},
        {"extensions": {"too_large": "x" * 8192}},
        {"extensions": {str(i): i for i in range(65)}},
    ],
)
def test_invalid_typed_or_bounded_fields_quarantine(raw: dict[str, Any]) -> None:
    with pytest.raises(NormalizationError) as error:
        event(raw)
    assert error.value.code == "invalid_event_fields"
    assert str(error.value) == "invalid_event_fields"


def test_conflicting_alias_does_not_silently_override_fact() -> None:
    with pytest.raises(NormalizationError, match="conflicting_event_fields"):
        event({"username": "alice", "user": {"name": "bob"}})


@pytest.mark.parametrize(
    "month_day,received,code",
    [
        ("Mar 29 02:30:00", datetime(2026, 3, 29, 1, 30, tzinfo=UTC), "nonexistent_local_time"),
        ("Oct 25 02:30:00", datetime(2026, 10, 25, 1, 30, tzinfo=UTC), "ambiguous_local_time"),
    ],
)
def test_syslog_dst_gap_and_overlap_quarantine(
    month_day: str, received: datetime, code: str
) -> None:
    context = replace(
        CONTEXT, source_type="linux_auth", timezone="Europe/Warsaw", received_at=received
    )
    raw = f"{month_day} host sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2"
    with pytest.raises(NormalizationError, match=code):
        normalize({"source_type": "linux_auth", "raw_event": raw}, context)


def test_syslog_iana_timezone_and_new_year_are_explicit() -> None:
    context = replace(CONTEXT, source_type="linux_auth", timezone="Europe/Warsaw")
    raw = "Jan  1 00:00:00 host sshd[1]: Accepted password for alice from 192.0.2.1 port 22 ssh2"
    result = normalize({"source_type": "linux_auth", "raw_event": raw}, context)
    assert result.timestamp == datetime(2025, 12, 31, 23, tzinfo=UTC)
    assert result.quality == ["inferred_year"]


def test_linux_iso_time_needs_no_inferred_year() -> None:
    raw = (
        "2026-01-01T01:00:00+01:00 host sshd[1]: "
        "Accepted password for alice from 192.0.2.1 port 22 ssh2"
    )
    assert event(raw, "linux_auth").quality == []


@pytest.mark.parametrize(
    "raw",
    [
        "Jan  1 00:00:00 host sshd[1]: Partial password for alice from 192.0.2.1 port 22 ssh2",
        "Jan  1 00:00:00 host unknown[1]: Accepted password for alice from 192.0.2.1 port 22 ssh2",
        "Feb 30 00:00:00 host sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2",
        "not a supported line",
    ],
)
def test_unsupported_or_invalid_linux_line_is_retained_as_quarantine(raw: str) -> None:
    with pytest.raises(NormalizationError):
        event(raw, "linux_auth")


def test_sudo_denied_is_failure_and_not_inferred_exploit() -> None:
    raw = (
        "Jan  1 00:00:00 host sudo[1]: alice : command not allowed ; "
        "TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh"
    )
    result = event(raw, "linux_auth")
    assert result.event.outcome == "failure"
    assert result.event.severity == "informational"
    assert result.user.target.name == "root"


def test_su_session_closed_without_actor_does_not_invent_one() -> None:
    raw = "Jan  1 00:00:00 host su[1]: pam_unix(su:session): session closed for user root"
    result = event(raw, "linux_auth")
    assert result.user.name is None
    assert result.user.target.name == "root"
    assert result.event.type == "end"
    assert result.event.outcome == "success"


def test_windows_success_session_preserves_scope_without_fabricating_host_id() -> None:
    result = event(
        {
            "EventID": 4624,
            "Computer": "PC-1",
            "EventData": {
                "TargetUserName": "alice",
                "TargetLogonId": "0x2ab",
                "IpAddress": "-",
                "IpPort": "0",
            },
        },
        "windows_auth",
    )
    assert result.session.id == "0x2ab"
    assert result.session.provider == "windows_security"
    assert result.session.host_id is None
    assert result.session.boot_id is None
    assert result.source.ip is None
    assert result.source.port == 0


def test_windows_missing_process_command_is_null_and_no_pid_entity() -> None:
    result = event(
        {
            "EventID": 4688,
            "System": {"Execution": {"ProcessID": 99}},
            "EventData": {
                "NewProcessId": "0x2a",
                "CommandLine": "",
                "NewProcessName": "C:\\Tools\\tool.exe",
            },
        },
        "windows_process",
    )
    assert result.process.pid == 42
    assert result.process.parent_pid is None
    assert result.process.command_line is None
    assert result.process.entity_id is None


@pytest.mark.parametrize(
    "source_type,raw",
    [
        ("windows_auth", {"EventID": 9999}),
        ("windows_process", {"EventID": 1, "ProviderName": "other provider"}),
        ("windows_process", {"EventID": 4688, "EventData": {"NewProcessId": "0xZZ"}}),
        ("firewall", "action=drop src=192.0.2.1 src=192.0.2.2"),
        ("firewall", "action=unknown src=192.0.2.1"),
        ("firewall", "action=drop dpt=70000"),
        ("nginx", "invalid combined log"),
        ("nginx", {"status": 403, "request": "not a request"}),
    ],
)
def test_invalid_adapter_contracts(source_type: str, raw: Any) -> None:
    with pytest.raises(NormalizationError):
        event(raw, source_type)


def test_nginx_default_hex_escape_decodes_unicode_and_quotes() -> None:
    raw = (
        r'192.0.2.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" '
        r'"Pawe\xC5\x82 \x22test\x22"'
    )
    result = event(raw, "nginx")
    assert result.http is not None
    assert result.http.user_agent == 'Paweł "test"'


def test_source_type_mismatch_is_integrity_failure() -> None:
    with pytest.raises(NormalizationError, match="source_type_mismatch"):
        normalize({"source_type": "nginx", "raw_event": {}}, CONTEXT)


def test_bounded_raw_and_safe_error_messages() -> None:
    with pytest.raises(NormalizationError) as error:
        event({"message": "secret" * 12000})
    assert "secret" not in str(error.value)
    assert NormalizationError("raw secret value").code == "normalization_failed"


def test_normalized_schema_rejects_unknown_metadata_and_quality() -> None:
    document = event({}).model_dump(mode="json")
    with pytest.raises(ValidationError):
        NormalizedSecurityEvent.model_validate({**document, "risk": 42})
    with pytest.raises(ValidationError):
        NormalizedSecurityEvent.model_validate({**document, "quality": ["arbitrary"]})


def test_normalized_schema_utc_conversion_is_stable() -> None:
    document = event({}).model_dump(mode="json")
    document["timestamp"] = "2026-01-01T01:00:00+01:00"
    document["processed_at"] = "2026-01-01T01:00:01+01:00"
    result = NormalizedSecurityEvent.model_validate(document)
    assert result.timestamp == CONTEXT.received_at
    assert result.processed_at == CONTEXT.processed_at


@pytest.mark.parametrize("ip", ["::ffff:192.0.2.5", "::ffff:c000:205", "0:0:0:0:0:ffff:c000:0205"])
def test_mapped_ipv6_serialization_is_canonical_in_both_directions(ip: str) -> None:
    result = event({"source_ip": ip, "destination_ip": ip}).model_dump(mode="json")
    assert result["source"]["ip"] == "::ffff:c000:205"
    assert result["destination"]["ip"] == "::ffff:c000:205"


def test_extensions_depth_and_raw_escaped_nul_are_bounded() -> None:
    child: dict[str, Any] = {"a": "safe"}
    for _ in range(6):
        child = {"a": child}
    with pytest.raises(NormalizationError):
        event({"extensions": child})
    with pytest.raises(NormalizationError):
        event(r'{"username":"alice\u0000"}')


def test_nginx_invalid_source_date_is_not_observation_fallback() -> None:
    raw = '192.0.2.1 - - [30/Feb/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "-"'
    with pytest.raises(NormalizationError, match="invalid_timestamp"):
        event(raw, "nginx")


@pytest.mark.parametrize(
    "timestamp", ["1969-12-31T23:59:59Z", "2300-01-01T00:00:00Z", "1970-01-01T00:00:00+01:00"]
)
def test_storage_time_bound_applies_to_envelope_and_raw(timestamp: str) -> None:
    with pytest.raises(NormalizationError, match="invalid_timestamp"):
        event({}, timestamp=timestamp)
    with pytest.raises(NormalizationError, match="invalid_timestamp"):
        event({"timestamp": timestamp})
