"""Six documented adapters; malformed source facts fail with redacted reason codes."""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PureWindowsPath
from typing import Any, cast
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import ValidationError

from app.modules.ingestion.schemas import RFC3339_TIMESTAMP, RawEnvelope
from app.modules.normalization.schemas import NormalizedSecurityEvent


@dataclass(frozen=True)
class NormalizationContext:
    event_id: UUID
    source_id: UUID
    dataset_id: UUID
    run_id: UUID
    source_event_id: str | None
    mode: str
    source_name: str
    source_type: str
    timezone: str
    received_at: datetime
    processed_at: datetime
    raw_sha256: str


class NormalizationError(ValueError):
    """Safe public reason; source text is never part of exception messages."""

    def __init__(self, code: str) -> None:
        self.code = code if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) else "normalization_failed"
        super().__init__(self.code)


@dataclass
class Parsed:
    fields: dict[str, Any]
    timestamp: datetime | None = None
    quality: list[str] | None = None


GENERIC_GROUPS = {
    "source": {"ip", "port"},
    "destination": {"ip", "port"},
    "host": {"id", "name", "os"},
    "user": {"id", "name", "realm", "target"},
    "session": {"id", "provider", "host_id", "boot_id"},
    "process": {
        "entity_id",
        "parent_entity_id",
        "name",
        "executable",
        "command_line",
        "pid",
        "parent_pid",
        "hash",
    },
    "event": {"category", "type", "action", "outcome", "severity", "code"},
    "network": {"protocol", "transport", "bytes", "packets"},
    "http": {"request_method", "url", "status_code", "version", "user_agent", "referrer", "bytes"},
    "file": {"name", "path", "hash"},
}
ALIASES = {
    "username": ("user", "name"),
    "hostname": ("host", "name"),
    "source_ip": ("source", "ip"),
    "source_port": ("source", "port"),
    "destination_ip": ("destination", "ip"),
    "destination_port": ("destination", "port"),
    "process_name": ("process", "name"),
    "command_line": ("process", "command_line"),
    "action": ("event", "action"),
    "severity": ("event", "severity"),
    "result": ("event", "outcome"),
}
SCOPE_FIELDS = {
    "event_id",
    "source_id",
    "dataset_id",
    "run_id",
    "mode",
    "received_at",
    "processed_at",
    "source_event_id",
    "schema_version",
    "parser_version",
    "raw_sha256",
    "source_type",
    "risk",
    "role",
    "quality",
}
MONTHS = {
    month: number
    for number, month in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}


def normalize(envelope: dict[str, Any], context: NormalizationContext) -> NormalizedSecurityEvent:
    try:
        checked = RawEnvelope.model_validate(envelope)
        if str(checked.source_type) != context.source_type:
            raise NormalizationError("source_type_mismatch")
        if context.received_at.tzinfo is None or context.processed_at.tzinfo is None:
            raise NormalizationError("invalid_context")
        zone = ZoneInfo(context.timezone)
        raw = checked.raw_event
        parsers = {
            "generic_json": _generic,
            "linux_auth": _linux,
            "windows_auth": _windows_auth,
            "windows_process": _windows_process,
            "firewall": _firewall,
            "nginx": _nginx,
        }
        parsed = parsers[context.source_type](raw, context, zone)
        quality = parsed.quality or []
        object_raw = raw if isinstance(raw, dict) else None
        if object_raw is None and context.source_type in {
            "generic_json",
            "windows_auth",
            "windows_process",
        }:
            object_raw = _object(raw)
        supplied = _raw_timestamp(object_raw) if object_raw is not None else None
        raw_time = _rfc3339(supplied) if supplied is not None else None
        timestamp = checked.timestamp or raw_time
        if timestamp is not None:
            quality = [flag for flag in quality if flag != "inferred_year"]
        if timestamp is None:
            timestamp = parsed.timestamp
        if timestamp is None:
            timestamp = context.received_at
            quality.extend(["timestamp_from_received_at", "missing_source_timestamp"])
        timestamp = _supported_time(timestamp)
        fields = parsed.fields
        source = fields.pop("source", {})
        source.update(name=context.source_name, type=context.source_type)
        return NormalizedSecurityEvent(
            event_id=context.event_id,
            source_id=context.source_id,
            dataset_id=context.dataset_id,
            run_id=context.run_id,
            source_event_id=context.source_event_id,
            mode=context.mode,
            timestamp=timestamp,
            received_at=context.received_at,
            processed_at=context.processed_at,
            raw_event=raw,
            raw_sha256=context.raw_sha256,
            source=source,
            quality=quality,
            **fields,
        )
    except NormalizationError:
        raise
    except (ValidationError, ValueError, TypeError, KeyError, OverflowError, ZoneInfoNotFoundError):
        raise NormalizationError("invalid_event_fields") from None


def _rfc3339(value: object) -> datetime:
    if not isinstance(value, str) or not RFC3339_TIMESTAMP.fullmatch(value):
        raise NormalizationError("invalid_timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return _supported_time(result)
    except (ValueError, OverflowError):
        raise NormalizationError("invalid_timestamp") from None


def _supported_time(value: datetime) -> datetime:
    result = value.astimezone(UTC)
    if not 1970 <= result.year < 2300:
        raise NormalizationError("invalid_timestamp")
    return result


def _raw_timestamp(raw: dict[str, Any]) -> object | None:
    for key in ("timestamp", "@timestamp", "event_time", "TimeCreated"):
        if key in raw:
            value = raw[key]
            if key == "TimeCreated" and isinstance(value, dict):
                result: object = value.get("SystemTime")
                return result
            return cast(object, value)
    system = raw.get("System")
    if isinstance(system, dict):
        created = system.get("TimeCreated")
        if isinstance(created, dict):
            return cast(object, created.get("SystemTime"))
    return None


def _object(raw: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise NormalizationError("invalid_json") from None
    if not isinstance(value, dict):
        raise NormalizationError("expected_json_object")
    RawEnvelope.validate_raw_event(value)
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("invalid JSON number")


def _generic(raw: str | dict[str, Any], context: NormalizationContext, zone: ZoneInfo) -> Parsed:
    data = _object(raw)
    fields: dict[str, Any] = {}
    quality: list[str] = []
    unknown = (
        set(data)
        - set(GENERIC_GROUPS)
        - set(ALIASES)
        - SCOPE_FIELDS
        - {"timestamp", "@timestamp", "event_time", "extensions", "message"}
    )
    if unknown:
        quality.append("unmapped_fields")
    if set(data) & SCOPE_FIELDS:
        quality.append("scope_fields_ignored")
    for group, allowed in GENERIC_GROUPS.items():
        if group not in data or data[group] is None:
            continue
        if not isinstance(data[group], dict):
            raise NormalizationError("invalid_event_fields")
        values = data[group]
        if group == "source" and ("name" in values or "type" in values):
            quality.append("scope_fields_ignored")
        if set(values) - allowed - ({"name", "type"} if group == "source" else set()):
            quality.append("unmapped_fields")
        fields[group] = {key: value for key, value in values.items() if key in allowed}
    for alias, (group, key) in ALIASES.items():
        if alias not in data:
            continue
        value = data[alias]
        if alias == "result":
            value = {"failed": "failure", "succeeded": "success"}.get(value, value)
        present = fields.setdefault(group, {})
        if key in present and present[key] != value:
            raise NormalizationError("conflicting_event_fields")
        present[key] = value
    if "extensions" in data:
        fields["extensions"] = data["extensions"]
    return Parsed(fields, quality=quality)


SYSLOG = re.compile(
    r"^(?:<\d{1,3}>)?(?P<time>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<host>[^\s]+) (?P<program>[A-Za-z0-9_.-]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$"
)
ISO_SYSLOG = re.compile(
    r"^(?:<\d{1,3}>)?(?P<time>\d{4}-\d{2}-\d{2}T[^\s]+) "
    r"(?P<host>[^\s]+) (?P<program>[A-Za-z0-9_.-]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$"
)
SSH = re.compile(
    r"^(?P<result>Accepted|Failed) (?P<method>\S+) for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2(?::.*|\s.*)?$"
)


def _local_time(value: datetime, zone: ZoneInfo) -> datetime:
    candidates: set[datetime] = set()
    for fold in (0, 1):
        aware = value.replace(tzinfo=zone, fold=fold)
        utc = aware.astimezone(UTC)
        if utc.astimezone(zone).replace(tzinfo=None) == value:
            candidates.add(utc)
    if not candidates:
        raise NormalizationError("nonexistent_local_time")
    if len(candidates) > 1:
        raise NormalizationError("ambiguous_local_time")
    return candidates.pop()


def _syslog_time(value: str, context: NormalizationContext, zone: ZoneInfo) -> datetime:
    # Numeric month table avoids locale-dependent strptime month names.
    parts = value.split()
    month, day = MONTHS.get(parts[0]), int(parts[1])
    if month is None:
        raise NormalizationError("invalid_timestamp")
    hour, minute, second = (int(part) for part in parts[2].split(":"))
    reference = context.received_at.astimezone(UTC)
    local_year = reference.astimezone(zone).year
    candidates: list[tuple[float, datetime]] = []
    for year in range(local_year - 1, local_year + 2):
        try:
            naive = datetime(year, month, day, hour, minute, second)
        except ValueError:
            continue
        # Select nearest wall time first; a nearest DST gap/overlap must quarantine,
        # rather than quietly moving the event to a different year.
        distance = abs((naive - reference.astimezone(zone).replace(tzinfo=None)).total_seconds())
        candidates.append((distance, naive))
    if not candidates:
        raise NormalizationError("invalid_timestamp")
    candidates.sort(key=lambda item: item[0])
    if len(candidates) > 1 and candidates[0][0] == candidates[1][0]:
        raise NormalizationError("ambiguous_syslog_year")
    return _local_time(candidates[0][1], zone)


def _linux(raw: str | dict[str, Any], context: NormalizationContext, zone: ZoneInfo) -> Parsed:
    data = _object(raw) if isinstance(raw, dict) else {}
    text = data.get("message") if data else raw
    if not isinstance(text, str):
        raise NormalizationError("invalid_linux_auth")
    match = SYSLOG.fullmatch(text)
    quality: list[str] = []
    timestamp = None
    if match:
        timestamp = _syslog_time(match["time"], context, zone)
        quality.append("inferred_year")
    else:
        match = ISO_SYSLOG.fullmatch(text)
        if match:
            timestamp = _rfc3339(match["time"])
    if match is None:
        raise NormalizationError("invalid_linux_auth")
    program, message = match["program"], match["message"]
    fields: dict[str, Any] = {
        "host": {"name": match["host"], "os": "linux"},
        "process": {"name": program, "pid": int(match["pid"]) if match["pid"] else None},
    }
    if program in {"sshd", "sshd-session"}:
        auth = SSH.fullmatch(message)
        if auth is None:
            raise NormalizationError("unsupported_linux_auth")
        fields.update(
            source={"ip": auth["ip"], "port": int(auth["port"])},
            user={"name": auth["user"]},
            event={
                "category": "authentication",
                "type": "start",
                "action": "ssh_login",
                "outcome": "success" if auth["result"] == "Accepted" else "failure",
                "severity": "informational" if auth["result"] == "Accepted" else "low",
            },
            extensions={
                "authentication_method": auth["method"],
                "invalid_user": bool(auth["invalid"]),
            },
        )
    elif program == "sudo":
        record = re.fullmatch(
            r"\s*(?P<actor>[^\s:]+)\s*:\s*(?P<details>.*?)(?:\s*;\s*)?"
            r"TTY=(?P<tty>[^;]*);\s*PWD=(?P<pwd>[^;]*);\s*USER=(?P<target>[^;]*);\s*"
            r"COMMAND=(?P<command>.+)",
            message,
        )
        if record is None:
            raise NormalizationError("unsupported_linux_auth")
        details = record["details"].strip()
        failure = any(
            marker in details
            for marker in (
                "NOT in sudoers",
                "command not allowed",
                "incorrect password",
                "authentication failure",
            )
        )
        fields.update(
            user={"name": record["actor"], "target": {"name": record["target"].strip()}},
            process={**fields["process"], "command_line": record["command"]},
            event={
                "category": "process",
                "type": "start",
                "action": "sudo_command",
                "outcome": "failure" if failure else "success",
                "severity": "informational",
            },
            extensions={"tty": record["tty"].strip(), "working_directory": record["pwd"].strip()},
        )
    elif program == "su":
        record = re.fullmatch(
            r"(?:pam_unix\(su(?:-l)?:session\): )?session (?P<action>opened|closed) for user "
            r"(?P<target>[^\s(]+)(?:\(uid=\d+\))?"
            r"(?: by (?P<actor>[^\s(]*)(?:\(uid=\d+\))?)?",
            message,
        )
        failed = re.fullmatch(
            r"FAILED SU \(to (?P<target>\S+)\) (?P<actor>\S+) on (?P<tty>\S+)", message
        )
        if record is None and failed is None:
            raise NormalizationError("unsupported_linux_auth")
        selected = record if record is not None else failed
        assert selected is not None
        fields.update(
            user={"name": selected["actor"] or None, "target": {"name": selected["target"]}},
            event={
                "category": "authentication",
                "type": "end" if record and record["action"] == "closed" else "start",
                "action": "su_session",
                "outcome": "failure" if failed else "success",
                "severity": "informational",
            },
        )
    else:
        raise NormalizationError("unsupported_linux_auth")
    return Parsed(fields, timestamp, quality)


def _clean(value: object) -> object | None:
    return None if value in (None, "", "-", "S-1-0-0") else value


def _windows_data(raw: str | dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
    data = _object(raw)
    system = data.get("System", {})
    if not isinstance(system, dict):
        raise NormalizationError("invalid_windows_event")
    event_data = data.get("EventData", data.get("event_data", data))
    if not isinstance(event_data, dict):
        raise NormalizationError("invalid_windows_event")
    code = data.get("EventID", data.get("event_id", system.get("EventID")))
    if isinstance(code, dict):
        code = code.get("Value")
    if type(code) not in (str, int) or not re.fullmatch(r"[0-9]{1,5}", str(code)):
        raise NormalizationError("invalid_windows_event")
    return data, event_data, str(code)


def _windows_base(data: dict[str, Any], values: dict[str, Any], code: str) -> dict[str, Any]:
    system = data.get("System", {})
    host_name = _clean(data.get("Computer", system.get("Computer")))
    host_id = _clean(data.get("host_id"))
    return {
        "host": {"name": host_name, "id": host_id, "os": "windows"},
        "user": {
            "id": _clean(values.get("SubjectUserSid")),
            "name": _clean(values.get("SubjectUserName")),
            "realm": _clean(values.get("SubjectDomainName")),
        },
        "event": {"code": code},
    }


def _account(values: dict[str, Any], prefix: str) -> dict[str, Any]:
    return {
        "id": _clean(values.get(prefix + "UserSid", values.get(prefix + "Sid"))),
        "name": _clean(values.get(prefix + "UserName")),
        "realm": _clean(values.get(prefix + "DomainName")),
    }


def _number(value: object, *, hexadecimal: bool = False) -> int | None:
    value = _clean(value)
    if value is None:
        return None
    if type(value) is int:
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        return int(value)
    if hexadecimal and isinstance(value, str) and re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        return int(value, 16)
    raise NormalizationError("invalid_event_fields")


def _windows_auth(
    raw: str | dict[str, Any], context: NormalizationContext, zone: ZoneInfo
) -> Parsed:
    data, values, code = _windows_data(raw)
    fields = _windows_base(data, values, code)
    if code in {"4624", "4625"}:
        fields["user"]["target"] = _account(values, "Target")
        fields.update(
            source={"ip": _clean(values.get("IpAddress")), "port": _number(values.get("IpPort"))},
            event={
                "code": code,
                "category": "authentication",
                "type": "start",
                "action": "windows_logon",
                "outcome": "success" if code == "4624" else "failure",
                "severity": "informational" if code == "4624" else "low",
            },
            extensions={
                key: values[key]
                for key in (
                    "LogonType",
                    "AuthenticationPackageName",
                    "Status",
                    "SubStatus",
                    "FailureReason",
                )
                if key in values
            },
        )
        if code == "4624":
            fields["session"] = {
                "id": _clean(values.get("TargetLogonId")),
                "provider": "windows_security",
                "host_id": fields["host"]["id"],
                "boot_id": _clean(data.get("boot_id")),
            }
    elif code == "4720":
        fields["user"]["target"] = _account(values, "Target")
        fields["event"] = {
            "code": code,
            "category": "iam",
            "type": "creation",
            "action": "user_created",
            "outcome": "success",
            "severity": "informational",
        }
    elif code == "4732":
        fields["user"]["target"] = {"id": _clean(values.get("MemberSid"))}
        fields["extensions"] = {
            "group": {
                "id": _clean(values.get("TargetSid")),
                "name": _clean(values.get("TargetUserName")),
                "realm": _clean(values.get("TargetDomainName")),
            },
            "member_distinguished_name": _clean(values.get("MemberName")),
        }
        fields["event"] = {
            "code": code,
            "category": "iam",
            "type": "change",
            "action": "group_member_added",
            "outcome": "success",
            "severity": "informational",
        }
    else:
        raise NormalizationError("unsupported_windows_event")
    return Parsed(fields)


def _windows_process(
    raw: str | dict[str, Any], context: NormalizationContext, zone: ZoneInfo
) -> Parsed:
    data, values, code = _windows_data(raw)
    fields = _windows_base(data, values, code)
    if code == "4688":
        executable = _clean(values.get("NewProcessName"))
        fields["user"]["target"] = _account(values, "Target")
        process = {
            "executable": executable,
            "name": PureWindowsPath(executable).name if isinstance(executable, str) else None,
            "command_line": _clean(values.get("CommandLine")),
            "pid": _number(values.get("NewProcessId"), hexadecimal=True),
            "parent_pid": _number(values.get("ProcessId"), hexadecimal=True),
        }
        extensions: dict[str, Any] = {"provider": "windows_security"}
        if "ParentProcessName" in values:
            extensions["parent_executable"] = _clean(values["ParentProcessName"])
        timestamp = None
    elif code == "1":
        provider = data.get("ProviderName", data.get("System", {}).get("Provider"))
        if isinstance(provider, dict):
            provider = provider.get("Name")
        if provider != "Microsoft-Windows-Sysmon":
            raise NormalizationError("unsupported_windows_event")
        executable = _clean(values.get("Image"))
        process = {
            "executable": executable,
            "name": PureWindowsPath(executable).name if isinstance(executable, str) else None,
            "command_line": _clean(values.get("CommandLine")),
            "pid": _number(values.get("ProcessId")),
            "parent_pid": _number(values.get("ParentProcessId")),
            "entity_id": _clean(values.get("ProcessGuid")),
            "parent_entity_id": _clean(values.get("ParentProcessGuid")),
            "hash": _clean(values.get("Hashes")),
        }
        username = _clean(values.get("User"))
        if isinstance(username, str):
            realm, separator, account = username.partition("\\")
            fields["user"] = {
                "name": account if separator else realm,
                "realm": realm if separator else None,
            }
        extensions = {"provider": "microsoft_windows_sysmon"}
        utc_time = values.get("UtcTime")
        if utc_time is None:
            timestamp = None
        elif isinstance(utc_time, str):
            timestamp = _rfc3339(
                utc_time.replace(" ", "T", 1) + "Z" if " " in utc_time else utc_time
            )
        else:
            raise NormalizationError("invalid_timestamp")
    else:
        raise NormalizationError("unsupported_windows_event")
    fields.update(
        process=process,
        extensions=extensions,
        event={
            "code": code,
            "category": "process",
            "type": "start",
            "action": "process_started",
            "outcome": "success",
            "severity": "informational",
        },
    )
    return Parsed(fields, timestamp)


def _firewall(raw: str | dict[str, Any], context: NormalizationContext, zone: ZoneInfo) -> Parsed:
    if isinstance(raw, dict):
        values = raw
    else:
        try:
            tokens = shlex.split(raw)
        except ValueError:
            raise NormalizationError("invalid_firewall_event") from None
        values = {}
        for token in tokens:
            key, separator, value = token.partition("=")
            if not separator or not key or key in values:
                raise NormalizationError("invalid_firewall_event")
            values[key] = value
    action = values.get("action")
    if not isinstance(action, str) or action.lower() not in {
        "allow",
        "accept",
        "deny",
        "drop",
        "reject",
    }:
        raise NormalizationError("invalid_firewall_event")
    action = action.lower()
    protocol = values.get("protocol", values.get("proto"))
    if protocol is not None and not isinstance(protocol, str):
        raise NormalizationError("invalid_firewall_event")
    fields: dict[str, Any] = {
        "source": {
            "ip": values.get("src", values.get("source_ip")),
            "port": _number(values.get("spt", values.get("source_port"))),
        },
        "destination": {
            "ip": values.get("dst", values.get("destination_ip")),
            "port": _number(values.get("dpt", values.get("destination_port"))),
        },
        "host": {"name": _clean(values.get("hostname"))},
        "network": {
            "transport": protocol.lower() if protocol else None,
            "bytes": _number(values.get("bytes")),
            "packets": _number(values.get("packets")),
        },
        "event": {
            "category": "network",
            "type": "connection",
            "action": action,
            "outcome": "success" if action in {"allow", "accept"} else "failure",
            "severity": "informational",
        },
    }
    timestamp = _rfc3339(values["timestamp"]) if "timestamp" in values else None
    return Parsed(fields, timestamp)


COMBINED = re.compile(
    r'^(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>(?:[^"\\]|\\.)*)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referrer>(?:[^"\\]|\\.)*)" '
    r'"(?P<agent>(?:[^"\\]|\\.)*)"$'
)


def _nginx_text(value: str) -> str | None:
    if value == "-":
        return None
    # Default nginx escaping emits hex bytes; decode UTF-8 after restoring bytes.
    result = bytearray()
    index = 0
    while index < len(value):
        if value[index : index + 2] == "\\x":
            if not re.fullmatch(r"[0-9a-fA-F]{2}", value[index + 2 : index + 4]):
                raise NormalizationError("invalid_nginx_event")
            result.append(int(value[index + 2 : index + 4], 16))
            index += 4
        else:
            result.extend(value[index].encode("utf-8"))
            index += 1
    try:
        return result.decode("utf-8")
    except UnicodeError:
        raise NormalizationError("invalid_nginx_event") from None


def _nginx(raw: str | dict[str, Any], context: NormalizationContext, zone: ZoneInfo) -> Parsed:
    timestamp = None
    if isinstance(raw, dict):
        values = raw
        request = _clean(values.get("request"))
        ip = _clean(values.get("remote_addr"))
        user = _clean(values.get("remote_user"))
        status = _number(values.get("status"))
        size = _number(values.get("body_bytes_sent"))
        referrer = _clean(values.get("http_referer"))
        agent = _clean(values.get("http_user_agent"))
        time_local = values.get("time_local")
    else:
        match = COMBINED.fullmatch(raw)
        if match is None:
            raise NormalizationError("invalid_nginx_event")
        request = _nginx_text(match["request"])
        ip, user = match["ip"], _clean(match["user"])
        status, size = _number(match["status"]), _number(match["bytes"])
        referrer, agent = _nginx_text(match["referrer"]), _nginx_text(match["agent"])
        time_local = match["time"]
    if time_local is not None:
        if not isinstance(time_local, str):
            raise NormalizationError("invalid_timestamp")
        timestamp = _clf_time(time_local)
    if status is None:
        raise NormalizationError("invalid_nginx_event")
    method = url = version = None
    if request is not None:
        if not isinstance(request, str):
            raise NormalizationError("invalid_nginx_event")
        parts = request.split(" ")
        if (
            len(parts) != 3
            or not re.fullmatch(r"[A-Z]+", parts[0])
            or not re.fullmatch(r"HTTP/\d(?:\.\d)?", parts[2])
        ):
            raise NormalizationError("invalid_nginx_event")
        method, url, version = parts
    return Parsed(
        {
            "source": {"ip": ip},
            "user": {"name": user},
            "http": {
                "request_method": method,
                "url": url,
                "version": version,
                "status_code": status,
                "bytes": size,
                "referrer": referrer,
                "user_agent": agent,
            },
            "event": {
                "category": "web",
                "type": "access",
                "action": "http_request",
                "outcome": "success" if status < 400 else "failure",
                "severity": "informational",
            },
        },
        timestamp,
    )


def _clf_time(value: str) -> datetime:
    match = re.fullmatch(
        r"(?P<day>\d{2})/(?P<month>[A-Z][a-z]{2})/(?P<year>\d{4}):"
        r"(?P<time>\d{2}:\d{2}:\d{2}) (?P<offset>[+-]\d{4})",
        value,
    )
    if match is None or match["month"] not in MONTHS:
        raise NormalizationError("invalid_timestamp")
    offset = match["offset"]
    return _rfc3339(
        f"{match['year']}-{MONTHS[match['month']]:02d}-{match['day']}T"
        f"{match['time']}{offset[:3]}:{offset[3:]}"
    )
