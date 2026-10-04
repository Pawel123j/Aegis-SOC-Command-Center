"""Source fidelity, bounded untrusted YAML and actual subset detection semantics."""

import hashlib
import json
from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.parsers import NormalizationContext, normalize
from app.modules.sigma.compiler import (
    EVALUATOR_VERSION,
    MAX_CONDITION_DEPTH,
    MAX_YAML_BYTES,
    SigmaValidationError,
    capabilities,
    compile_rule,
)
from app.modules.sigma.evaluator import CompiledRuleError, evaluate

SIGMA_ID = "5946167f-0d59-4c36-9f9b-556ed30a01c7"


def source(
    detection: dict[str, Any] | None = None,
    *,
    logsource: dict[str, str] | None = None,
    **metadata: Any,
) -> str:
    return json.dumps(
        {
            "title": "Controlled process rule",
            "id": SIGMA_ID,
            "logsource": logsource or {"product": "windows", "category": "process_creation"},
            "detection": detection
            or {"selection": {"Image|endswith": "powershell.exe"}, "condition": "selection"},
            **metadata,
        },
        ensure_ascii=False,
    )


def process_document(**overrides: Any) -> dict[str, Any]:
    return {
        "source": {"type": "windows_process"},
        "event": {"category": "process", "type": "start", "action": "process_started", "code": "1"},
        "process": {
            "name": "powershell.exe",
            "executable": r"C:\Windows\PowerShell.exe",
            "command_line": "pwsh -enc RwA=",
            "pid": 42,
        },
        "host": {"name": "WORKSTATION-1"},
        "user": {"name": "Paweł", "target": {"name": "root"}},
        **overrides,
    }


def test_metadata_hashes_dates_and_frozen_copy_contract() -> None:
    text = """title: Kontrolowana reguła
id: 5946167f-0d59-4c36-9f9b-556ed30a01c7
description: Sygnał do weryfikacji
date: 2026-10-03
modified: '2026-10-03'
author: Test
license: MIT
status: test
level: high
tags: [attack.execution, attack.t1059.001]
references: ['https://attack.mitre.org/techniques/T1059/001/']
falsepositives: ['Approved administration']
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\powershell.exe'
  condition: selection
"""
    rule = compile_rule(text)
    assert rule.sigma_id == UUID(SIGMA_ID)
    assert rule.date == rule.modified == "2026-10-03"
    assert rule.status == "test" and rule.severity == "high"
    assert rule.author == "Test" and rule.license == "MIT"
    assert rule.mitre == ("T1059.001",)
    assert rule.source_sha256 == hashlib.sha256(text.encode()).hexdigest()
    assert rule.compiled_sha256 == hashlib.sha256(canonical_json(rule.as_dict())).hexdigest()
    snapshot = rule.snapshot()
    assert snapshot["type"] == "sigma" and snapshot["evaluator_version"] == EVALUATOR_VERSION
    assert snapshot["id"] == f"sigma:{SIGMA_ID}"
    assert snapshot["mitre"] == ["T1059.001"]
    copy = rule.as_dict()
    copy["selections"].clear()
    snapshot["mitre"].clear()
    assert rule.as_dict()["selections"] and rule.mitre == ("T1059.001",)
    with pytest.raises(FrozenInstanceError):
        rule.title = "modified"  # type: ignore[misc]
    assert compile_rule(text) == rule
    commented = compile_rule("# preserved input comment\n" + text)
    assert commented.compiled_sha256 == rule.compiled_sha256
    assert commented.source_sha256 != rule.source_sha256


@pytest.mark.parametrize(
    ("field", "expected", "actual", "matches"),
    [
        ("process.name", "POWERSHELL.EXE", "powershell.exe", True),
        ("process.name", "power", "powershell.exe", False),
        ("process.name|contains", "SHELL", "powershell.exe", True),
        ("process.name|contains", "CMD", "powershell.exe", False),
        ("process.name|startswith", "PoWeR", "powershell.exe", True),
        ("process.name|startswith", "shell", "powershell.exe", False),
        ("process.name|endswith", ".EXE", "powershell.exe", True),
        ("process.name|endswith", "shell", "powershell.exe", False),
        ("user.name", "STRAßE", "strasse", True),
        ("user.target.name", "ROOT", "root", True),
        ("process.executable|endswith", r"\\POWERSHELL.exe", r"C:\Windows\powershell.exe", True),
    ],
)
def test_case_insensitive_supported_operators(
    field: str,
    expected: str,
    actual: str,
    matches: bool,
) -> None:
    rule = compile_rule(source({"selection": {field: expected}, "condition": "selection"}))
    document = process_document()
    path = field.split("|")[0].split(".")
    target = document
    for item in path[:-1]:
        target = target[item]
    target[path[-1]] = actual
    before = deepcopy(document)
    reason = evaluate(rule, document)
    assert bool(reason) is matches
    assert document == before
    if reason:
        assert reason["matched_fields"][field.split("|")[0]] == actual
        assert reason["matched_selections"] == ["selection"]
        reason["condition"].clear()
        assert evaluate(rule.as_dict(), document)


def test_map_and_list_semantics_do_not_flatten_fields() -> None:
    rule = compile_rule(
        source(
            {
                "selection": [
                    {
                        "Image|endswith": ["powershell.exe", "pwsh.exe"],
                        "CommandLine|contains": "-enc",
                    },
                    {"Image|endswith": "cmd.exe", "CommandLine|contains": "/c whoami"},
                ],
                "condition": "selection",
            }
        )
    )
    assert evaluate(rule, process_document())
    assert evaluate(
        rule, process_document(process={"executable": "pwsh.exe", "command_line": "pwsh -enc x"})
    )
    assert evaluate(
        rule, process_document(process={"executable": "cmd.exe", "command_line": "cmd /c whoami"})
    )
    assert (
        evaluate(
            rule, process_document(process={"executable": "cmd.exe", "command_line": "cmd -enc x"})
        )
        is None
    )
    assert (
        evaluate(
            rule,
            process_document(
                process={"executable": "powershell.exe", "command_line": "pwsh ordinary"}
            ),
        )
        is None
    )


@pytest.mark.parametrize(
    ("condition", "a", "b", "c", "expected"),
    [
        ("a and b", True, False, False, False),
        ("a OR b", False, True, False, True),
        ("a or b and c", True, False, False, True),
        ("a or b and c", False, True, False, False),
        ("(a or b) and c", True, False, False, False),
        ("a AND NOT (b OR c)", True, False, False, True),
        ("a and not (b or c)", True, True, False, False),
        ("not not a", True, False, False, True),
    ],
)
def test_boolean_precedence_parentheses_and_negation(
    condition: str,
    a: bool,
    b: bool,
    c: bool,
    expected: bool,
) -> None:
    rule = compile_rule(
        source(
            {
                "a": {"process.name": "a"},
                "b": {"host.name": "b"},
                "c": {"user.name": "c"},
                "condition": condition,
            }
        )
    )
    document = process_document(
        process={"name": "a" if a else "other"},
        host={"name": "b" if b else "other"},
        user={"name": "c" if c else "other"},
    )
    assert bool(evaluate(rule, document)) is expected


def test_missing_field_and_boolean_not_are_explicit_source_facts() -> None:
    positive = compile_rule(
        source({"selection": {"process.command_line|contains": "-enc"}, "condition": "selection"})
    )
    negative = compile_rule(
        source(
            {"selection": {"process.command_line|contains": "-enc"}, "condition": "not selection"}
        )
    )
    for value in (
        {},
        {"command_line": None},
        {"command_line": 42},
        {"command_line": ""},
        {"command_line": "\x00-enc"},
        {"command_line": "x" * 8193},
    ):
        document = process_document(process=value)
        assert evaluate(positive, document) is None
        reason = evaluate(negative, document)
        assert reason and reason["matched_fields"] == {} and reason["matched_selections"] == []
    assert evaluate(negative, process_document(source={"type": "generic_json"})) is None


@pytest.mark.parametrize(
    ("service", "code", "matches"),
    [
        ("sysmon", "1", True),
        ("sysmon", "4688", False),
        ("security", "4688", True),
        ("security", "1", False),
    ],
)
def test_explicit_provider_guard_and_numeric_event_id(
    service: str, code: str, matches: bool
) -> None:
    rule = compile_rule(
        source(
            {"selection": {"EventID": [1, 4688]}, "condition": "selection"},
            logsource={"product": "windows", "category": "process_creation", "service": service},
        )
    )
    document = process_document()
    document["event"]["code"] = code
    assert bool(evaluate(rule, document)) is matches
    assert rule.as_dict()["selections"]["selection"][0][0]["values"] == ["1", "4688"]


def test_normalizer_to_sigma_actual_process_pipeline() -> None:
    context = NormalizationContext(
        event_id=UUID(int=1),
        source_id=UUID(int=2),
        dataset_id=UUID(int=3),
        run_id=UUID(int=0),
        source_event_id="test",
        mode="live",
        source_name="controlled",
        source_type="windows_process",
        timezone="UTC",
        received_at=datetime(2026, 10, 3, tzinfo=UTC),
        processed_at=datetime(2026, 10, 3, tzinfo=UTC),
        raw_sha256="ab" * 32,
    )
    event = normalize(
        {
            "source_type": "windows_process",
            "raw_event": {
                "EventID": 4688,
                "Computer": "WIN-1",
                "EventData": {
                    "NewProcessName": r"C:\Windows\PowerShell.exe",
                    "CommandLine": "powershell -enc RwA=",
                    "SubjectUserName": "admin",
                    "NewProcessId": "0x2a",
                },
            },
        },
        context,
    )
    rule = compile_rule(
        source(
            {
                "selection": {
                    "NewProcessName|endswith": "powershell.exe",
                    "EventID": 4688,
                    "NewProcessId": 42,
                },
                "condition": "selection",
            },
            logsource={"product": "windows", "category": "process_creation", "service": "security"},
        )
    )
    reason = evaluate(rule, event.model_dump(mode="json"))
    assert reason and reason["matched_fields"]["process.pid"] == 42


@pytest.mark.parametrize(
    ("logsource", "field", "value", "document"),
    [
        (
            {"product": "windows", "service": "security"},
            "EventID",
            4625,
            {"source": {"type": "windows_auth"}, "event": {"code": "4625"}},
        ),
        (
            {"product": "linux", "service": "sshd"},
            "event.outcome",
            "failure",
            {
                "source": {"type": "linux_auth"},
                "process": {"name": "sshd-session"},
                "event": {"outcome": "failure"},
            },
        ),
        (
            {"product": "linux", "service": "sudo"},
            "user.target.name",
            "root",
            {
                "source": {"type": "linux_auth"},
                "process": {"name": "sudo"},
                "user": {"target": {"name": "root"}},
            },
        ),
        (
            {"product": "linux", "service": "su"},
            "user.target.name",
            "root",
            {
                "source": {"type": "linux_auth"},
                "process": {"name": "su"},
                "user": {"target": {"name": "root"}},
            },
        ),
        (
            {"product": "linux", "service": "auth"},
            "event.outcome",
            "failure",
            {"source": {"type": "linux_auth"}, "event": {"outcome": "failure"}},
        ),
        (
            {"category": "firewall"},
            "dst_ip",
            "203.0.113.4",
            {
                "source": {"type": "firewall"},
                "event": {"category": "network"},
                "destination": {"ip": "203.0.113.4"},
            },
        ),
        (
            {"category": "webserver", "service": "nginx"},
            "sc-status",
            403,
            {
                "source": {"type": "nginx"},
                "event": {"category": "web"},
                "http": {"status_code": 403},
            },
        ),
        (
            {"product": "aegis", "service": "generic_json"},
            "event.action",
            "example",
            {"source": {"type": "generic_json"}, "event": {"action": "example"}},
        ),
    ],
)
def test_supported_sources_are_explicit_and_never_cross_match(
    logsource: dict[str, str],
    field: str,
    value: Any,
    document: dict[str, Any],
) -> None:
    rule = compile_rule(
        source({"selection": {field: value}, "condition": "selection"}, logsource=logsource)
    )
    assert evaluate(rule, document)
    document["source"]["type"] = "different"
    assert evaluate(rule, document) is None


@pytest.mark.parametrize(
    "field",
    [
        "Password",
        "ParentImage",
        "TargetUserName",
        "process.__class__",
        "extensions.custom",
        "raw_event",
        "command_line",
        "NewProcessName",
    ],
)
def test_unsupported_or_ambiguous_fields_rejected_even_unused(field: str) -> None:
    with pytest.raises(SigmaValidationError) as error:
        compile_rule(
            source(
                {
                    "selection": {"Image": "powershell.exe"},
                    "unused": {field: "secret-input"},
                    "condition": "selection",
                }
            )
        )
    assert error.value.code == "unsupported_field"
    assert "secret-input" not in str(error.value)


@pytest.mark.parametrize(
    "modifier",
    [
        "re",
        "cidr",
        "exists",
        "all",
        "cased",
        "base64",
        "contains|all",
        "equals",
        "contains|",
        "invalid",
    ],
)
def test_unsupported_modifiers_never_fall_back_to_equality(modifier: str) -> None:
    with pytest.raises(SigmaValidationError) as error:
        compile_rule(
            source({"selection": {f"Image|{modifier}": "secret-input"}, "condition": "selection"})
        )
    assert error.value.code == "unsupported_modifier"


@pytest.mark.parametrize(
    "value", ["*powershell.exe", "powershell.?xe", r"\*powershell.exe", None, True, 1.5, {}, 42, ""]
)
def test_unsupported_detection_values_rejected(value: Any) -> None:
    with pytest.raises(SigmaValidationError):
        compile_rule(source({"selection": {"Image": value}, "condition": "selection"}))


@pytest.mark.parametrize(
    "condition",
    [
        "1 of selection*",
        "all of them",
        "selection | count() > 3",
        "selection and",
        "(selection",
        "selection)",
        "selection unknown",
        "missing",
        "__import__('os')",
        "selection + selection",
        ["selection"],
        "",
        "éxample",
    ],
)
def test_unsupported_or_malformed_condition_rejected(condition: Any) -> None:
    with pytest.raises(SigmaValidationError):
        compile_rule(source({"selection": {"Image": "powershell.exe"}, "condition": condition}))


@pytest.mark.parametrize(
    "logsource",
    [
        {},
        {"product": "windows"},
        {"product": "linux", "category": "process_creation"},
        {"category": "network_connection", "product": "windows"},
        {"product": "windows", "service": "sysmon"},
        {"category": "webserver"},
        {"category": "firewall", "service": "unknown"},
        {"product": "windows", "category": "process_creation", "definition": "ignored"},
        {"product": "windows", "category": True},
    ],
)
def test_unsupported_logsource_is_never_broadened(logsource: dict[str, Any]) -> None:
    document = json.loads(source())
    document["logsource"] = logsource
    with pytest.raises(SigmaValidationError):
        compile_rule(json.dumps(document))


@pytest.mark.parametrize(
    "yaml_text",
    [
        "!!python/object/apply:os.system ['should never execute']",
        "title: !!str explicit",
        "title: &anchor value\nid: *anchor",
        "title: &anchor value",
        "---\ntitle: first\n---\ntitle: second",
        "%YAML 1.1\n---\ntitle: value",
        "title: first\ntitle: second",
        "detection: {selection: {Image: one, Image: two}}",
        "title: value\n<<: {id: value}",
        "[not, a, map]",
        "title: [unclosed",
        "title: value\n1: numeric-key",
        "title: value\nnull: null-key",
        "",
        "title: nul\x00value",
    ],
)
def test_yaml_structures_and_unsafe_tags_reject_without_side_effect(yaml_text: str) -> None:
    with pytest.raises(SigmaValidationError) as error:
        compile_rule(yaml_text)
    assert "should never execute" not in str(error.value)


@pytest.mark.parametrize(
    "metadata",
    [
        {"id": "invalid"},
        {"id": "00000000-0000-0000-0000-000000000000"},
        {"id": None},
        {"title": True},
        {"title": ""},
        {"level": "invalid"},
        {"status": "invalid"},
        {"date": "2026/10/03"},
        {"modified": "2026-02-30"},
        {"date": "20261003"},
        {"author": []},
        {"references": ["javascript:alert(1)"]},
        {"references": ["https://user:password@example.com/"]},
        {"references": ["https://[bad/"]},
        {"references": ["https://example.com", "https://example.com"]},
        {"tags": ["attack.t9999"]},
        {"tags": ["attack.defense-evasion"]},
        {"tags": ["attack.invalid"]},
        {"tags": "attack.execution"},
        {"fields": ["Image"]},
        {"correlation": {}},
    ],
)
def test_metadata_is_bounded_and_unsupported_fields_are_explicit(metadata: dict[str, Any]) -> None:
    with pytest.raises(SigmaValidationError):
        compile_rule(source(**metadata))


def test_rule_budgets_cover_bytes_depth_nodes_selectors_values_and_condition() -> None:
    with pytest.raises(SigmaValidationError) as error:
        compile_rule(source(description="Ł" * MAX_YAML_BYTES))
    assert error.value.code == "yaml_size"
    with pytest.raises(SigmaValidationError) as error:
        compile_rule("title: " + "[" * 13 + "value" + "]" * 13)
    assert error.value.code == "yaml_depth"
    with pytest.raises(SigmaValidationError) as error:
        compile_rule("title: [" + ",".join("a" for _ in range(2050)) + "]")
    assert error.value.code == "yaml_nodes"
    with pytest.raises(SigmaValidationError) as error:
        compile_rule(source({**{f"s{i}": {"Image": "x"} for i in range(33)}, "condition": "s0"}))
    assert error.value.code == "selection_count"
    with pytest.raises(SigmaValidationError) as error:
        compile_rule(source({"selection": {"Image": ["x"] * 129}, "condition": "selection"}))
    assert error.value.code == "value_count"
    with pytest.raises(SigmaValidationError) as error:
        compile_rule(
            source({**{f"s{i}": {"Image": ["x"] * 128} for i in range(5)}, "condition": "s0"})
        )
    assert error.value.code == "selection_budget"
    with pytest.raises(SigmaValidationError) as error:
        compile_rule(
            source(
                {
                    "selection": {"Image": "x"},
                    "condition": "not " * MAX_CONDITION_DEPTH + "selection",
                }
            )
        )
    assert error.value.code == "condition_depth"
    with pytest.raises(SigmaValidationError) as error:
        compile_rule(
            source({"selection": {"Image": "x"}, "condition": " or ".join(["selection"] * 65)})
        )
    assert error.value.code == "condition_tokens"


@pytest.mark.parametrize(
    "selection", [[], {}, ["keyword"], [{}, {"Image": "x"}], {"Image": []}, {"Image": [["x"]]}]
)
def test_selection_shapes_are_never_silently_accepted(selection: Any) -> None:
    with pytest.raises(SigmaValidationError):
        compile_rule(source({"selection": selection, "condition": "selection"}))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda ast: ast.update(evaluator_version="unknown"),
        lambda ast: ast.update(schema_version=True),
        lambda ast: ast.update(extra="unsupported"),
        lambda ast: ast.update(source_filters=[]),
        lambda ast: ast.update(selections={}),
        lambda ast: ast.update(condition={"kind": "eval", "name": "selection"}),
        lambda ast: ast.update(condition={"kind": "selection", "name": "unknown"}),
        lambda ast: ast.update(condition={"kind": "not"}),
        lambda ast: ast.update(condition={"kind": "and", "items": []}),
        lambda ast: ast.update(condition={"kind": []}),
        lambda ast: ast["selections"]["selection"][0][0].update(field="raw_event"),
        lambda ast: ast["selections"]["selection"][0][0].update(operator=[]),
        lambda ast: ast["selections"]["selection"][0][0].update(values=[]),
        lambda ast: ast["selections"]["selection"][0][0].update(values=[None]),
    ],
)
def test_corrupt_or_unknown_ast_cannot_execute(mutation: Any) -> None:
    compiled = compile_rule(source()).as_dict()
    mutation(compiled)
    with pytest.raises(CompiledRuleError):
        evaluate(compiled, process_document())


def test_capabilities_are_consistent_reproducible_and_return_fresh_data() -> None:
    data = capabilities()
    assert data["max_yaml_bytes"] == MAX_YAML_BYTES == 65536
    assert data["evaluator_version"] == EVALUATOR_VERSION
    assert data["operators"] == ["equals", "contains", "startswith", "endswith"]
    assert "process.command_line" in data["fields"] and "raw_event" not in data["fields"]
    for profile in data["logsources"]:
        rule = (
            compile_rule(source(logsource=profile["logsource"]))
            if profile["source_type"] == "windows_process"
            else compile_rule(
                source(
                    {"selection": {"event.action": "example"}, "condition": "selection"},
                    logsource=profile["logsource"],
                )
            )
        )
        assert rule.source_types == (profile["source_type"],)
    data["fields"].clear()
    assert capabilities()["fields"]


def test_yaml_byte_limit_accepts_exact_boundary_and_counts_utf8() -> None:
    definition = source(title="Reguła Łódź") + "\n#"
    exact = definition + "x" * (MAX_YAML_BYTES - len(definition.encode("utf-8")))
    rule = compile_rule(exact)
    assert rule.title == "Reguła Łódź" and evaluate(rule, process_document())
    with pytest.raises(SigmaValidationError) as error:
        compile_rule(exact + "x")
    assert error.value.code == "yaml_size"
    with pytest.raises(SigmaValidationError) as error:
        compile_rule(exact[:-1] + "Ł")
    assert error.value.code == "yaml_size"
    with pytest.raises(SigmaValidationError) as error:
        compile_rule(source(title="\ud800"))
    assert error.value.code == "yaml_encoding"


@pytest.mark.parametrize(
    ("field", "valid", "invalid"),
    [
        ("source.port", [0, 65535], [-1, 65536, True, "443"]),
        ("destination.port", [0, 65535], [-1, 65536, False]),
        ("process.pid", [0, 4294967295], [-1, 4294967296, 42.0]),
        ("process.parent_pid", [0, 4294967295], [-1, 4294967296]),
        ("network.bytes", [0, 9223372036854775807], [-1, 9223372036854775808]),
        ("network.packets", [0, 9223372036854775807], [-1, 9223372036854775808]),
        ("http.status_code", [100, 599], [0, 99, 600, 65535]),
        ("http.bytes", [0, 9223372036854775807], [-1, 9223372036854775808]),
    ],
)
def test_integer_predicates_preserve_normalized_types_and_storage_ranges(
    field: str, valid: list[int], invalid: list[Any]
) -> None:
    rule = compile_rule(
        source(
            {"selection": {field: valid}, "condition": "selection"},
            logsource={"product": "aegis", "service": "generic_json"},
        )
    )
    parent, name = field.split(".")
    for item in valid:
        document: dict[str, Any] = {"source": {"type": "generic_json"}}
        document.setdefault(parent, {})[name] = item
        assert evaluate(rule, document)
    for item in invalid:
        with pytest.raises(SigmaValidationError):
            compile_rule(
                source(
                    {"selection": {field: item}, "condition": "selection"},
                    logsource={"product": "aegis", "service": "generic_json"},
                )
            )
        document = {"source": {"type": "generic_json"}}
        document.setdefault(parent, {})[name] = item
        assert evaluate(rule, document) is None


@pytest.mark.parametrize(
    ("service", "alias", "field", "value"),
    [
        ("security", "NewProcessId", "process.pid", 42),
        ("security", "SubjectUserName", "user.name", "admin"),
        ("sysmon", "ProcessId", "process.pid", 42),
        ("sysmon", "ParentProcessId", "process.parent_pid", 7),
        ("sysmon", "ProcessGuid", "process.entity_id", "guid-example"),
    ],
)
def test_provider_aliases_match_only_their_verified_normalized_fact(
    service: str, alias: str, field: str, value: str | int
) -> None:
    profile = {"product": "windows", "category": "process_creation", "service": service}
    rule = compile_rule(
        source({"selection": {alias: value}, "condition": "selection"}, logsource=profile)
    )
    document = process_document()
    parent, name = field.split(".")
    document[parent][name] = value
    document["event"]["code"] = "4688" if service == "security" else "1"
    assert evaluate(rule, document)
    other = {**profile, "service": "sysmon" if service == "security" else "security"}
    with pytest.raises(SigmaValidationError) as error:
        compile_rule(
            source({"selection": {alias: value}, "condition": "selection"}, logsource=other)
        )
    assert error.value.code == "unsupported_field"


def test_corrupt_compiled_recursion_and_integer_type_are_rejected_before_matching() -> None:
    rule = compile_rule(source()).as_dict()
    nested = {"kind": "selection", "name": "selection"}
    for _ in range(MAX_CONDITION_DEPTH):
        nested = {"kind": "not", "item": nested}
    rule["condition"] = nested
    with pytest.raises(CompiledRuleError):
        evaluate(rule, process_document())
    integer = compile_rule(
        source({"selection": {"process.pid": 42}, "condition": "selection"})
    ).as_dict()
    integer["selections"]["selection"][0][0]["values"] = [True]
    with pytest.raises(CompiledRuleError):
        evaluate(integer, process_document())
