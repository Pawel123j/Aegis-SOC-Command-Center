"""Versioned, bounded normalized event contract; source facts remain separate from risk."""

from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, PlainSerializer, field_validator

from app.modules.ingestion.schemas import RawEnvelope, canonical_json

Text = Annotated[str, Field(strict=True, min_length=1, max_length=1024)]
ShortText = Annotated[str, Field(strict=True, min_length=1, max_length=256)]
Port = Annotated[int, Field(strict=True, ge=0, le=65535)]
Pid = Annotated[int, Field(strict=True, ge=0, le=4294967295)]


def canonical_ip(value: IPv4Address | IPv6Address) -> str:
    """Mapped IPv6 uses hexadecimal consistently across Python patch versions."""
    if isinstance(value, IPv6Address) and value.ipv4_mapped is not None:
        mapped = int(value.ipv4_mapped)
        return f"::ffff:{mapped >> 16:x}:{mapped & 65535:x}"
    return str(value)


Ip = Annotated[
    IPv4Address | IPv6Address,
    PlainSerializer(canonical_ip, return_type=str, when_used="json"),
]
QualityFlag = Literal[
    "timestamp_from_received_at",
    "inferred_year",
    "scope_fields_ignored",
    "unmapped_fields",
    "missing_source_timestamp",
]


class EventObject(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    @field_validator("*", mode="before")
    @classmethod
    def no_nul(cls, value: object) -> object:
        if isinstance(value, str) and "\x00" in value:
            raise ValueError("text fields cannot contain NUL")
        return value

    @field_validator("ip", mode="before", check_fields=False)
    @classmethod
    def typed_ip(cls, value: object) -> object:
        if value is not None and not isinstance(value, (str, IPv4Address, IPv6Address)):
            raise ValueError("an IP string is required")
        return value


class Source(EventObject):
    name: ShortText
    type: Literal[
        "generic_json", "linux_auth", "windows_auth", "windows_process", "firewall", "nginx"
    ]
    ip: Ip | None = None
    port: Port | None = None


class Destination(EventObject):
    ip: Ip | None = None
    port: Port | None = None


class Host(EventObject):
    id: ShortText | None = None
    name: ShortText | None = None
    os: ShortText | None = None


class Account(EventObject):
    id: ShortText | None = None
    name: ShortText | None = None
    realm: ShortText | None = None


class User(Account):
    target: Account = Field(default_factory=Account)


class Session(EventObject):
    id: ShortText | None = None
    provider: ShortText | None = None
    host_id: ShortText | None = None
    boot_id: ShortText | None = None


class Process(EventObject):
    entity_id: ShortText | None = None
    parent_entity_id: ShortText | None = None
    name: ShortText | None = None
    executable: Text | None = None
    command_line: Annotated[str, Field(strict=True, min_length=1, max_length=8192)] | None = None
    pid: Pid | None = None
    parent_pid: Pid | None = None
    hash: Text | None = None


class Event(EventObject):
    category: ShortText = "unknown"
    type: ShortText = "unknown"
    action: ShortText = "unknown"
    outcome: Literal["success", "failure", "unknown"] = "unknown"
    severity: Literal["informational", "low", "medium", "high", "critical"] = "informational"
    code: ShortText | None = None


class Network(EventObject):
    protocol: ShortText | None = None
    transport: ShortText | None = None
    bytes: Annotated[int, Field(strict=True, ge=0, le=9223372036854775807)] | None = None
    packets: Annotated[int, Field(strict=True, ge=0, le=9223372036854775807)] | None = None


class Http(EventObject):
    request_method: ShortText | None = None
    url: Annotated[str, Field(strict=True, min_length=1, max_length=8192)] | None = None
    status_code: Annotated[int, Field(strict=True, ge=100, le=599)] | None = None
    version: ShortText | None = None
    user_agent: Text | None = None
    referrer: Annotated[str, Field(strict=True, min_length=1, max_length=8192)] | None = None
    bytes: Annotated[int, Field(strict=True, ge=0, le=9223372036854775807)] | None = None


class File(EventObject):
    name: ShortText | None = None
    path: Text | None = None
    hash: Text | None = None


class NormalizedSecurityEvent(EventObject):
    schema_version: Literal["1.0"] = "1.0"
    parser_version: Literal["1.0.0"] = "1.0.0"
    event_id: UUID
    source_id: UUID
    dataset_id: UUID
    run_id: UUID
    source_event_id: Annotated[str, Field(strict=True, min_length=1, max_length=128)] | None = None
    mode: Literal["live", "replay"]
    timestamp: AwareDatetime
    received_at: AwareDatetime
    processed_at: AwareDatetime
    source: Source
    destination: Destination = Field(default_factory=Destination)
    host: Host = Field(default_factory=Host)
    user: User = Field(default_factory=User)
    session: Session = Field(default_factory=Session)
    process: Process = Field(default_factory=Process)
    event: Event = Field(default_factory=Event)
    network: Network | None = None
    http: Http | None = None
    file: File | None = None
    raw_event: str | dict[str, Any]
    raw_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$", strict=True)]
    extensions: dict[str, Any] = Field(default_factory=dict)
    quality: Annotated[list[QualityFlag], Field(max_length=16)] = Field(default_factory=list)

    @field_validator("timestamp", "received_at", "processed_at")
    @classmethod
    def utc(cls, value: datetime) -> datetime:
        result = value.astimezone(UTC)
        if not 1970 <= result.year < 2300:
            raise ValueError("event timestamps must be within the supported storage range")
        return result

    @field_validator("raw_event", mode="before")
    @classmethod
    def bounded_raw(cls, value: object) -> object:
        return RawEnvelope.validate_raw_event(value)

    @field_validator("extensions")
    @classmethod
    def bounded_extensions(cls, value: dict[str, Any]) -> dict[str, Any]:
        RawEnvelope.validate_raw_event(value)
        if len(value) > 64 or len(canonical_json(value)) > 8192:
            raise ValueError("extensions exceed the bounded adapter contract")
        stack: list[tuple[object, int]] = [(value, 1)]
        while stack:
            item, depth = stack.pop()
            if isinstance(item, dict):
                if depth > 6 or any(len(key) > 128 for key in item):
                    raise ValueError("extensions exceed the bounded adapter contract")
                stack.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                if depth > 6 or len(item) > 128:
                    raise ValueError("extensions exceed the bounded adapter contract")
                stack.extend((child, depth + 1) for child in item)
        return value

    @field_validator("quality")
    @classmethod
    def unique_quality(cls, value: list[QualityFlag]) -> list[QualityFlag]:
        return list(dict.fromkeys(value))
