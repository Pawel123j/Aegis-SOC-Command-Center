"""A bounded, explicit Sigma subset compiled to data, never executable expressions.

Maps combine fields with AND; lists combine alternatives with OR. All supported
strings use case-insensitive matching. Wildcards and unsupported Sigma semantics
are rejected rather than silently converted to different detection behaviour.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from app.modules.mitre.catalogue import catalogue
from app.modules.sigma.conditions import (
    MAX_CONDITION_DEPTH as MAX_CONDITION_DEPTH,
)
from app.modules.sigma.conditions import (
    MAX_CONDITION_LENGTH as MAX_CONDITION_LENGTH,
)
from app.modules.sigma.conditions import (
    MAX_CONDITION_TOKENS as MAX_CONDITION_TOKENS,
)
from app.modules.sigma.conditions import (
    ConditionParser,
)
from app.modules.sigma.yaml_support import (
    MAX_NODES as MAX_NODES,
)
from app.modules.sigma.yaml_support import (
    MAX_YAML_BYTES as MAX_YAML_BYTES,
)
from app.modules.sigma.yaml_support import (
    MAX_YAML_DEPTH as MAX_YAML_DEPTH,
)
from app.modules.sigma.yaml_support import (
    SigmaValidationError as SigmaValidationError,
)
from app.modules.sigma.yaml_support import (
    _reject,
    parse_yaml,
)

EVALUATOR_VERSION = "sigma-subset-v1"
MAX_SELECTIONS = 32
MAX_PREDICATES = 256
MAX_VALUES = 512
MAX_VALUES_PER_FIELD = 128
MAX_VALUE_LENGTH = 8192

_ROOT_FIELDS = frozenset(
    {
        "title",
        "id",
        "description",
        "status",
        "author",
        "license",
        "date",
        "modified",
        "references",
        "tags",
        "falsepositives",
        "level",
        "logsource",
        "detection",
    }
)
_LEVELS = frozenset({"informational", "low", "medium", "high", "critical"})
_STATUSES = frozenset({"stable", "test", "experimental", "deprecated", "unsupported"})
_OPERATORS = frozenset({"equals", "contains", "startswith", "endswith"})
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_TECHNIQUE_TAG = re.compile(r"attack\.(t[0-9]{4}(?:\.[0-9]{3})?)\Z")

# Only facts already defined by the normalized schema are addressable. No raw
# event, credential, arbitrary extension or Python object access is available.
STRING_FIELDS = frozenset(
    {
        "source.name",
        "source.type",
        "source.ip",
        "destination.ip",
        "host.id",
        "host.name",
        "host.os",
        "user.id",
        "user.name",
        "user.realm",
        "user.target.id",
        "user.target.name",
        "user.target.realm",
        "process.entity_id",
        "process.parent_entity_id",
        "process.name",
        "process.executable",
        "process.command_line",
        "process.hash",
        "event.category",
        "event.type",
        "event.action",
        "event.outcome",
        "event.severity",
        "event.code",
        "network.protocol",
        "network.transport",
        "http.request_method",
        "http.url",
        "http.version",
        "http.user_agent",
        "http.referrer",
        "file.name",
        "file.path",
        "file.hash",
    }
)
INTEGER_FIELDS = frozenset(
    {
        "source.port",
        "destination.port",
        "process.pid",
        "process.parent_pid",
        "network.bytes",
        "network.packets",
        "http.status_code",
        "http.bytes",
    }
)
INTEGER_BOUNDS = {
    "source.port": (0, 65535),
    "destination.port": (0, 65535),
    "process.pid": (0, 4294967295),
    "process.parent_pid": (0, 4294967295),
    "network.bytes": (0, 9223372036854775807),
    "network.packets": (0, 9223372036854775807),
    "http.status_code": (100, 599),
    "http.bytes": (0, 9223372036854775807),
}
ALLOWED_FIELDS = STRING_FIELDS | INTEGER_FIELDS


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _text(value: Any, path: str, *, maximum: int = 4096, optional: bool = False) -> str:
    if optional and value is None:
        return ""
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or "\x00" in value
        or any(ord(character) < 32 and character not in "\t\r\n" for character in value)
    ):
        _reject("text_value", "A bounded nonempty text value is required.", path)
    return value


def _optional_text(document: dict[str, Any], key: str, maximum: int = 256) -> str | None:
    return _text(document[key], key, maximum=maximum) if key in document else None


def _text_list(document: dict[str, Any], key: str, *, maximum: int = 32) -> tuple[str, ...]:
    values = document.get(key, [])
    if not isinstance(values, list) or len(values) > maximum:
        _reject("metadata_list", "A bounded list of text values is required.", key)
    result = tuple(_text(value, key, maximum=2048) for value in values)
    if len(set(result)) != len(result):
        _reject("metadata_duplicate", "Metadata lists must contain unique values.", key)
    return result


def _logsource(value: Any) -> tuple[dict[str, str], list[dict[str, Any]]]:
    if not isinstance(value, dict) or not value or set(value) - {"product", "category", "service"}:
        _reject(
            "logsource",
            "An explicit supported product/category/service mapping is required.",
            "logsource",
        )
    source = {key: _text(item, f"logsource.{key}", maximum=64) for key, item in value.items()}
    product, category, service = (source.get(key) for key in ("product", "category", "service"))
    source_type: str | None = None
    filters: list[dict[str, Any]] = []

    def guard(field: str, *values: str) -> None:
        filters.append({"field": field, "operator": "equals", "values": list(values)})

    if (
        product == "windows"
        and category == "process_creation"
        and service in {None, "security", "sysmon"}
    ):
        source_type = "windows_process"
        guard("event.category", "process")
        guard("event.type", "start")
        guard("event.action", "process_started")
        guard(
            "event.code",
            *("4688",)
            if service == "security"
            else ("1",)
            if service == "sysmon"
            else ("4688", "1"),
        )
    elif product == "windows" and category is None and service == "security":
        source_type = "windows_auth"
        guard("event.code", "4624", "4625", "4720", "4732")
    elif product == "linux" and category is None and service in {"auth", "sshd", "sudo", "su"}:
        source_type = "linux_auth"
        if service != "auth":
            guard("process.name", *("sshd", "sshd-session") if service == "sshd" else (service,))
    elif product is None and category == "firewall" and service is None:
        source_type = "firewall"
        guard("event.category", "network")
    elif product is None and category == "webserver" and service == "nginx":
        source_type = "nginx"
        guard("event.category", "web")
    elif product == "aegis" and category is None and service == "generic_json":
        source_type = "generic_json"
    if source_type is None:
        _reject(
            "unsupported_logsource",
            "This logsource is not supported by an Aegis normalized adapter.",
            "logsource",
        )
    filters.insert(0, {"field": "source.type", "operator": "equals", "values": [source_type]})
    return source, filters


def _resolve_field(name: str, source: dict[str, str], source_type: str) -> tuple[str, bool]:
    if name in ALLOWED_FIELDS:
        return name, False
    aliases: dict[str, str] = {}
    if source_type in {"windows_process", "windows_auth"}:
        aliases.update(EventID="event.code", Computer="host.name")
        if source_type == "windows_auth" or source.get("service") == "security":
            aliases.update(
                SubjectUserName="user.name",
                SubjectUserSid="user.id",
                SubjectDomainName="user.realm",
            )
    if source_type == "windows_process":
        aliases.update(Image="process.executable", CommandLine="process.command_line")
        if source.get("service") == "security":
            aliases.update(NewProcessName="process.executable", NewProcessId="process.pid")
        elif source.get("service") == "sysmon":
            aliases.update(
                ProcessId="process.pid",
                ParentProcessId="process.parent_pid",
                ProcessGuid="process.entity_id",
                ParentProcessGuid="process.parent_entity_id",
            )
    elif source_type == "windows_auth":
        aliases.update(IpAddress="source.ip", IpPort="source.port")
    elif source_type == "firewall":
        aliases.update(
            src_ip="source.ip",
            dst_ip="destination.ip",
            src_port="source.port",
            dst_port="destination.port",
        )
    elif source_type == "nginx":
        aliases.update(
            {
                "c-ip": "source.ip",
                "cs-method": "http.request_method",
                "c-uri": "http.url",
                "sc-status": "http.status_code",
                "c-useragent": "http.user_agent",
            }
        )
    if name not in aliases:
        _reject(
            "unsupported_field",
            "This field or alias is not supported for the selected logsource.",
            "detection",
        )
    return aliases[name], name == "EventID"


def _value(value: Any, field: str, operator: str, event_id_alias: bool) -> str | int:
    if type(value) is int:
        if field in INTEGER_FIELDS:
            lower, upper = INTEGER_BOUNDS[field]
            if operator != "equals" or not lower <= value <= upper:
                _reject(
                    "integer_value",
                    "Integer fields support equality within their normalized schema bounds only.",
                    "detection",
                )
            return value
        if event_id_alias and 0 <= value <= 2147483647 and operator == "equals":
            return str(value)
        _reject(
            "scalar_type",
            "Integer values require an integer field or the EventID equality alias.",
            "detection",
        )
    text = _text(value, "detection", maximum=MAX_VALUE_LENGTH)
    if "*" in text or "?" in text:
        _reject(
            "unsupported_wildcard",
            "Sigma wildcards and escaped wildcard literals are unsupported; "
            "use a supported modifier.",
            "detection",
        )
    if field in INTEGER_FIELDS:
        _reject(
            "scalar_type",
            "Integer normalized fields require a YAML integer equality value.",
            "detection",
        )
    # Sigma doubles a literal backslash. Wildcard escape semantics are deliberately
    # excluded above; ordinary Windows paths keep their single backslashes.
    return text.replace("\\\\", "\\")


def _selections(
    detection: dict[str, Any], source: dict[str, str], source_type: str
) -> dict[str, Any]:
    names = [name for name in detection if name != "condition"]
    if not 1 <= len(names) <= MAX_SELECTIONS:
        _reject("selection_count", "A rule requires between 1 and 32 selections.", "detection")
    results: dict[str, Any] = {}
    predicates = total_values = 0
    for name in names:
        if not _IDENTIFIER.fullmatch(name) or name.casefold() in {"and", "or", "not"}:
            _reject(
                "selection_name", "Selections need bounded nonreserved identifiers.", "detection"
            )
        selection = detection[name]
        alternatives = selection if isinstance(selection, list) else [selection]
        if not alternatives or len(alternatives) > MAX_SELECTIONS:
            _reject(
                "selection_map",
                "Selections must be nonempty maps or bounded lists of maps.",
                "detection",
            )
        maps = []
        for alternative in alternatives:
            if not isinstance(alternative, dict) or not alternative:
                _reject(
                    "selection_map",
                    "Keyword and empty selections are unsupported; use field maps.",
                    "detection",
                )
            terms = []
            for field_name, raw_values in alternative.items():
                parts = field_name.split("|")
                operator = parts[1] if len(parts) == 2 else "equals"
                if (
                    len(parts) > 2
                    or operator not in _OPERATORS
                    or (len(parts) == 2 and operator == "equals")
                ):
                    _reject(
                        "unsupported_modifier",
                        "Only equals, contains, startswith and endswith are supported, "
                        "without modifier chains.",
                        "detection",
                    )
                field, event_id_alias = _resolve_field(parts[0], source, source_type)
                values = raw_values if isinstance(raw_values, list) else [raw_values]
                if not 1 <= len(values) <= MAX_VALUES_PER_FIELD:
                    _reject(
                        "value_count", "A field requires between 1 and 128 values.", "detection"
                    )
                compiled_values = [
                    _value(value, field, operator, event_id_alias) for value in values
                ]
                predicates += 1
                total_values += len(compiled_values)
                if predicates > MAX_PREDICATES or total_values > MAX_VALUES:
                    _reject(
                        "selection_budget",
                        "The rule exceeds its predicate or total value budget.",
                        "detection",
                    )
                terms.append({"field": field, "operator": operator, "values": compiled_values})
            maps.append(terms)
        results[name] = maps
    return results


def capabilities() -> dict[str, Any]:
    """One source of truth for validation limits and UI/API guidance."""
    sources = [
        {"product": "windows", "category": "process_creation"},
        {"product": "windows", "category": "process_creation", "service": "sysmon"},
        {"product": "windows", "category": "process_creation", "service": "security"},
        {"product": "windows", "service": "security"},
        *[{"product": "linux", "service": service} for service in ("auth", "sshd", "sudo", "su")],
        {"category": "firewall"},
        {"category": "webserver", "service": "nginx"},
        {"product": "aegis", "service": "generic_json"},
    ]
    aliases = (
        "EventID",
        "Computer",
        "SubjectUserName",
        "SubjectUserSid",
        "SubjectDomainName",
        "Image",
        "CommandLine",
        "NewProcessName",
        "NewProcessId",
        "ProcessId",
        "ParentProcessId",
        "ProcessGuid",
        "ParentProcessGuid",
        "IpAddress",
        "IpPort",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "c-ip",
        "cs-method",
        "c-uri",
        "sc-status",
        "c-useragent",
    )
    profiles = []
    for source in sources:
        _, filters = _logsource(source)
        source_type = filters[0]["values"][0]
        field_aliases = {}
        for alias in aliases:
            try:
                field_aliases[alias] = _resolve_field(alias, source, source_type)[0]
            except SigmaValidationError:
                continue
        profiles.append({"logsource": source, "source_type": source_type, "aliases": field_aliases})
    return {
        "evaluator_version": EVALUATOR_VERSION,
        "max_yaml_bytes": MAX_YAML_BYTES,
        "max_selections": MAX_SELECTIONS,
        "max_predicates": MAX_PREDICATES,
        "max_values": MAX_VALUES,
        "max_values_per_field": MAX_VALUES_PER_FIELD,
        "max_value_length": MAX_VALUE_LENGTH,
        "max_condition_length": MAX_CONDITION_LENGTH,
        "max_condition_tokens": MAX_CONDITION_TOKENS,
        "max_condition_depth": MAX_CONDITION_DEPTH,
        "max_yaml_nodes": MAX_NODES,
        "max_yaml_depth": MAX_YAML_DEPTH,
        "operators": ["equals", "contains", "startswith", "endswith"],
        "boolean_operators": ["AND", "OR", "NOT"],
        "fields": sorted(ALLOWED_FIELDS),
        "integer_fields": sorted(INTEGER_FIELDS),
        "logsources": profiles,
        "limitations": [
            "One explicit non-nil UUID is required; missing level defaults to medium.",
            "String comparisons are case-insensitive; a bare field means equality.",
            "Maps use AND, lists use OR; NOT of a nonmatching or missing-field selection is true.",
            "Unsupported: wildcards, regex, keyword selections, null/exists, "
            "modifier chains, aggregation and correlation.",
            "Unsupported: YAML tags, anchors, aliases, merges, directives, "
            "duplicate keys and multiple documents.",
            "Aliases depend on the exact logsource; "
            "arbitrary raw fields and extensions are unavailable.",
        ],
    }


@dataclass(frozen=True, slots=True)
class CompiledRule:
    sigma_id: UUID
    title: str
    description: str
    severity: str
    status: str | None
    author: str | None
    license: str | None
    date: str | None
    modified: str | None
    tags: tuple[str, ...]
    mitre: tuple[str, ...]
    false_positive_guidance: tuple[str, ...]
    references: tuple[str, ...]
    logsource: tuple[tuple[str, str], ...]
    source_types: tuple[str, ...]
    source_sha256: str
    compiled_sha256: str
    _compiled_json: str

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = json.loads(self._compiled_json)
        return result

    def snapshot(self) -> dict[str, Any]:
        return {
            **self.as_dict()["metadata"],
            "id": f"sigma:{self.sigma_id}",
            "version": "1",
            "type": "sigma",
            "evaluator_version": EVALUATOR_VERSION,
            "source_sha256": self.source_sha256,
            "compiled_sha256": self.compiled_sha256,
        }


def compile_rule(yaml_text: str) -> CompiledRule:
    document = parse_yaml(yaml_text)
    if set(document) - _ROOT_FIELDS:
        _reject(
            "unsupported_attribute",
            "This rule contains attributes outside the supported Sigma subset.",
        )
    title = _text(document.get("title"), "title", maximum=256)
    identity = _text(document.get("id"), "id", maximum=36)
    try:
        sigma_id = UUID(identity)
    except ValueError:
        _reject("rule_id", "A standard non-nil Sigma UUID is required.", "id")
    if str(sigma_id) != identity.lower() or sigma_id.int == 0:
        _reject("rule_id", "A standard non-nil Sigma UUID is required.", "id")
    description = _text(document.get("description"), "description", optional=True)
    severity = document.get("level", "medium")
    if not isinstance(severity, str) or severity not in _LEVELS:
        _reject("level", "Unsupported Sigma level.", "level")
    optional = {
        key: _optional_text(document, key)
        for key in ("status", "author", "license", "date", "modified")
    }
    if optional["status"] is not None and optional["status"] not in _STATUSES:
        _reject("status", "Unsupported Sigma status.", "status")
    for key in ("date", "modified"):
        if optional[key] is not None:
            try:
                parsed = date.fromisoformat(optional[key] or "")
            except ValueError:
                _reject("date", "Metadata dates must use YYYY-MM-DD.", key)
            if parsed.isoformat() != optional[key]:
                _reject("date", "Metadata dates must use YYYY-MM-DD.", key)
    tags = _text_list(document, "tags", maximum=40)
    techniques: list[str] = []
    for tag in tags:
        if tag.startswith("attack."):
            match = _TECHNIQUE_TAG.fullmatch(tag)
            if match is not None:
                technique = match.group(1).upper()
                try:
                    catalogue().technique(technique)
                except ValueError:
                    _reject(
                        "mitre_tag",
                        "Technique tags must identify an active technique in the pinned catalogue.",
                        "tags",
                    )
                techniques.append(technique)
            elif not any(
                item.active and f"attack.{item.short_name}" == tag for item in catalogue().tactics
            ):
                _reject("mitre_tag", "Unknown or unsupported ATT&CK tag.", "tags")
    if len(techniques) > 20 or len(set(techniques)) != len(techniques):
        _reject("mitre_tag", "Technique tags must be bounded and unique.", "tags")
    references, false_positives = (
        _text_list(document, key) for key in ("references", "falsepositives")
    )
    for reference in references:
        try:
            url = urlsplit(reference)
            valid = (
                url.scheme in {"http", "https"}
                and url.hostname is not None
                and not url.username
                and not url.password
            )
        except ValueError:
            valid = False
        if not valid:
            _reject(
                "reference_url",
                "References require HTTP(S) URLs without embedded credentials.",
                "references",
            )
    source, source_filters = _logsource(document.get("logsource"))
    detection = document.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        _reject("detection", "A detection map with a condition is required.", "detection")
    selections = _selections(detection, source, source_filters[0]["values"][0])
    condition_text = _text(
        detection["condition"], "detection.condition", maximum=MAX_CONDITION_LENGTH
    )
    condition = ConditionParser(condition_text, set(selections)).parse()
    metadata = {
        "sigma_id": str(sigma_id),
        "title": title,
        "description": description,
        "severity": severity,
        **optional,
        "tags": list(tags),
        "mitre": sorted(techniques),
        "references": list(references),
        "false_positive_guidance": list(false_positives),
        "logsource": source,
    }
    compiled_json = _canonical(
        {
            "schema_version": 1,
            "evaluator_version": EVALUATOR_VERSION,
            "metadata": metadata,
            "source_filters": source_filters,
            "selections": selections,
            "condition": condition,
        }
    )
    return CompiledRule(
        sigma_id=sigma_id,
        title=title,
        description=description,
        severity=severity,
        status=optional["status"],
        author=optional["author"],
        license=optional["license"],
        date=optional["date"],
        modified=optional["modified"],
        tags=tags,
        mitre=tuple(sorted(techniques)),
        references=references,
        false_positive_guidance=false_positives,
        logsource=tuple(sorted(source.items())),
        source_types=(source_filters[0]["values"][0],),
        source_sha256=hashlib.sha256(yaml_text.encode("utf-8")).hexdigest(),
        compiled_sha256=hashlib.sha256(compiled_json.encode("utf-8")).hexdigest(),
        _compiled_json=compiled_json,
    )
