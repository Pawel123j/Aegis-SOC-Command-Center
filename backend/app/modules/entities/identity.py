"""Conservative, deterministic profiles of observed facts, independent of correlation keys.

An identity is a source assertion, never an inventory or account verification. In
particular, PIDs, process names and well-known Windows SIDs cannot join hosts.
"""

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import UUID, uuid5

from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.schemas import Account, NormalizedSecurityEvent, canonical_ip

IDENTITY_POLICY = "entity-identity-v1"
MAX_ENTITY_DESCRIPTORS = 8
IDENTITY_NAMESPACE = UUID("39053be2-a811-52cb-84e3-6a20fdba1810")
EntityType = Literal["host", "user", "ip", "process"]
IdentityStrength = Literal["source_scoped", "host_scoped", "event_local", "network_address"]

_SID = re.compile(r"S-1-([0-9]{1,15})((?:-[0-9]{1,10}){1,15})\Z", re.ASCII)
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z", re.ASCII)


@dataclass(frozen=True, slots=True)
class EntityDescriptor:
    entity_id: UUID
    entity_type: EntityType
    canonical_key: dict[str, str]
    key_sha256: str
    identity_strength: IdentityStrength
    role: str
    label: str
    attributes: dict[str, str | int]
    timestamp: datetime
    policy_version: str = IDENTITY_POLICY


def _observed(value: str | None) -> str | None:
    """Do not rewrite opaque facts or turn the usual absent marker into an identity."""
    return value if value is not None and value.strip() and value != "-" else None


def _windows(event: NormalizedSecurityEvent) -> bool:
    return (
        event.source.type in {"windows_auth", "windows_process"}
        or (event.host.os or "").casefold() == "windows"
    )


def _sid(value: str | None) -> str | None:
    """Bound the official textual SID structure; a syntactically valid SID is unverified."""
    if value is None:
        return None
    match = _SID.fullmatch(value)
    if match is None:
        return None
    authority = int(match[1])
    subauthorities = tuple(int(part) for part in match[2].split("-")[1:])
    if authority >= 2**48 or any(part >= 2**32 for part in subauthorities):
        return None
    result = f"S-1-{authority}" + "".join(f"-{part}" for part in subauthorities)
    return None if result == "S-1-0-0" else result


def _account_sid(value: str) -> bool:
    """Full machine/domain or Entra account shape; well-known SIDs repeat between hosts."""
    parts = value.split("-")
    return len(parts) == 8 and (parts[2:4] == ["5", "21"] or parts[2:4] == ["12", "1"])


def _hostname(value: str, windows: bool) -> str:
    candidate = value.removesuffix(".")
    dns = len(candidate) <= 253 and all(
        _DNS_LABEL.fullmatch(label) is not None for label in candidate.split(".")
    )
    if dns:
        return candidate.lower()
    return value.casefold() if windows else value


def _process_identifier(value: str | None, windows: bool) -> str | None:
    value = _observed(value)
    if value in (None, "0", "0x0"):
        return None
    try:
        identifier = UUID(value)
    except ValueError:
        return value
    if identifier.int == 0:
        return None
    return str(identifier) if windows else value


def _scope(event: NormalizedSecurityEvent) -> dict[str, str]:
    if event.mode == "live":
        if event.run_id.int != 0:
            raise ValueError("live entity scope requires the live run")
        return {"mode": "live", "dataset_id": "", "run_id": str(UUID(int=0))}
    if event.dataset_id.int == 0 or event.run_id.int == 0:
        raise ValueError("replay entity scope requires exact dataset and nonzero run")
    return {
        "mode": "replay",
        "dataset_id": str(event.dataset_id),
        "run_id": str(event.run_id),
    }


def extract_entity_descriptors(
    document: dict[str, Any] | NormalizedSecurityEvent,
) -> tuple[EntityDescriptor, ...]:
    """Extract at most seven roles from a validated immutable normalized snapshot.

    The hash covers only canonical scope and identity, excluding timestamps,
    labels, observed aliases and contributor role. Role is a separate relation.
    Every result owns its dictionaries so callers cannot mutate the input or a
    different descriptor. Missing host context makes weak identities event local.
    """
    event = NormalizedSecurityEvent.model_validate(
        document.model_dump(mode="json")
        if isinstance(document, NormalizedSecurityEvent)
        else document
    )
    scope = _scope(event)
    windows = _windows(event)
    descriptors: list[EntityDescriptor] = []

    def append(
        kind: EntityType,
        role: str,
        identity: dict[str, str],
        strength: IdentityStrength,
        label: str,
        attributes: dict[str, str | int],
        *,
        global_address: bool = False,
    ) -> EntityDescriptor:
        key = {"policy": IDENTITY_POLICY, "kind": kind, **scope}
        if not global_address:
            key["source_id"] = str(event.source_id)
        key.update(identity)
        digest = hashlib.sha256(canonical_json(key)).hexdigest()
        descriptor = EntityDescriptor(
            entity_id=uuid5(IDENTITY_NAMESPACE, digest),
            entity_type=kind,
            canonical_key=key,
            key_sha256=digest,
            identity_strength=strength,
            role=role,
            label=label[:256],
            attributes=dict(attributes),
            timestamp=event.timestamp,
        )
        descriptors.append(descriptor)
        return descriptor

    host_id, host_name = _observed(event.host.id), _observed(event.host.name)
    host: EntityDescriptor | None = None
    host_attributes: dict[str, str | int] = {
        name: value
        for name, value in (
            ("host_id", host_id),
            ("host_name", host_name),
            ("host_os", event.host.os),
        )
        if value is not None
    }
    if host_id is not None:
        host = append(
            "host",
            "host",
            {"basis": "host_id", "value": host_id},
            "source_scoped",
            host_id,
            host_attributes,
        )
    elif host_name is not None:
        hostname = _hostname(host_name, windows)
        host = append(
            "host",
            "host",
            {"basis": "host_name", "value": hostname},
            "source_scoped",
            hostname,
            host_attributes,
        )

    def context() -> tuple[dict[str, str], IdentityStrength]:
        return (
            ({"host_key_sha256": host.key_sha256}, "host_scoped")
            if host is not None
            else ({"event_id": str(event.event_id)}, "event_local")
        )

    def account_descriptor(account: Account, role: str) -> None:
        account_id = _observed(account.id)
        name, realm = _observed(account.name), _observed(account.realm)
        sid = _sid(account_id) if windows else None
        attributes: dict[str, str | int] = {
            key: value
            for key, value in (("account_id", account_id), ("user_name", name), ("realm", realm))
            if value is not None
        }
        identity, strength = context()
        if sid is not None:
            if _account_sid(sid):
                identity, strength = {}, "source_scoped"
            identity.update({"basis": "windows_sid", "value": sid})
            label = sid
        elif not windows and account_id is not None:
            identity.update({"basis": "account_id", "value": account_id, "realm": realm or ""})
            label = account_id
        elif name is not None:
            canonical_name = name.casefold() if windows else name
            canonical_realm = realm.casefold() if realm is not None and windows else realm or ""
            identity.update(
                {
                    "basis": "account_name",
                    "value": canonical_name,
                    "realm": canonical_realm,
                    "name_case": "windows_casefold" if windows else "exact",
                }
            )
            label = canonical_name
        else:
            return
        append("user", role, identity, strength, label, attributes)

    account_descriptor(event.user, "actor")
    account_descriptor(event.user.target, "target")

    for role, address in (("source", event.source.ip), ("destination", event.destination.ip)):
        if address is not None:
            ip = canonical_ip(address)
            append(
                "ip",
                role,
                {"basis": "ip_address", "value": ip},
                "network_address",
                ip,
                {"address": ip},
                global_address=True,
            )

    def process_descriptor(parent: bool) -> None:
        process = event.process
        entity_id = _process_identifier(
            process.parent_entity_id if parent else process.entity_id, windows
        )
        pid = process.parent_pid if parent else process.pid
        name = None if parent else _observed(process.name)
        executable = None if parent else _observed(process.executable)
        process_hash = None if parent else _observed(process.hash)
        if (
            entity_id is None
            and pid is None
            and name is None
            and executable is None
            and process_hash is None
        ):
            return
        identity, strength = context()
        if entity_id is not None and host is not None:
            identity.update({"basis": "process_entity_id", "value": entity_id})
            label = entity_id
        else:
            # PID reuse, process names and even command lines cannot identify an instance.
            identity = {
                "basis": "process_event",
                "event_id": str(event.event_id),
                "process_role": "parent" if parent else "process",
            }
            strength = "event_local"
            observed_label = (
                entity_id
                or name
                or executable
                or (f"PID {pid}" if pid is not None else process_hash)
            )
            assert observed_label is not None
            label = observed_label
        attributes: dict[str, str | int] = {
            key: value
            for key, value in (
                ("entity_id", entity_id),
                ("pid", pid),
                ("process_name", name),
                ("executable", executable),
                ("hash", process_hash),
            )
            if value is not None
        }
        append("process", "parent" if parent else "process", identity, strength, label, attributes)

    process_descriptor(False)
    process_descriptor(True)
    if len(descriptors) > MAX_ENTITY_DESCRIPTORS:
        raise ValueError("entity extraction exceeded its bounded contract")
    return tuple(descriptors)
