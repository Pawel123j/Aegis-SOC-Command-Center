"""Pure bounded evaluation of the compiled Sigma data contract on source facts."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Never

from app.modules.sigma.compiler import (
    ALLOWED_FIELDS,
    EVALUATOR_VERSION,
    INTEGER_BOUNDS,
    INTEGER_FIELDS,
    MAX_CONDITION_DEPTH,
    MAX_CONDITION_TOKENS,
    MAX_PREDICATES,
    MAX_SELECTIONS,
    MAX_VALUE_LENGTH,
    MAX_VALUES,
    MAX_VALUES_PER_FIELD,
    CompiledRule,
)


class CompiledRuleError(ValueError):
    """An unsupported/corrupt compiled definition must never be evaluated."""


def _invalid() -> Never:
    raise CompiledRuleError("Invalid compiled Sigma subset definition.")


def _predicate(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"field", "operator", "values"}:
        _invalid()
    field, operator, values = (value[key] for key in ("field", "operator", "values"))
    if (
        not isinstance(field, str)
        or field not in ALLOWED_FIELDS
        or not isinstance(operator, str)
        or operator not in {"equals", "contains", "startswith", "endswith"}
        or not isinstance(values, list)
        or not 1 <= len(values) <= MAX_VALUES_PER_FIELD
    ):
        _invalid()
    for item in values:
        if field in INTEGER_FIELDS:
            lower, upper = INTEGER_BOUNDS[field]
            if type(item) is not int or operator != "equals" or not lower <= item <= upper:
                _invalid()
        elif not isinstance(item, str) or not 1 <= len(item) <= MAX_VALUE_LENGTH or "\x00" in item:
            _invalid()
    return value


def _condition(node: Any, names: set[str], budget: list[int], depth: int = 1) -> None:
    budget[0] += 1
    if (
        depth > MAX_CONDITION_DEPTH
        or budget[0] > MAX_CONDITION_TOKENS
        or not isinstance(node, dict)
    ):
        _invalid()
    kind = node.get("kind")
    if not isinstance(kind, str):
        _invalid()
    if kind == "selection":
        if (
            set(node) != {"kind", "name"}
            or not isinstance(node["name"], str)
            or node["name"] not in names
        ):
            _invalid()
    elif kind == "not":
        if set(node) != {"kind", "item"}:
            _invalid()
        _condition(node["item"], names, budget, depth + 1)
    elif kind in {"and", "or"}:
        if (
            set(node) != {"kind", "items"}
            or not isinstance(node["items"], list)
            or not 2 <= len(node["items"]) <= MAX_CONDITION_TOKENS
        ):
            _invalid()
        for child in node["items"]:
            _condition(child, names, budget, depth + 1)
    else:
        _invalid()


def _validate(compiled: dict[str, Any]) -> None:
    if (
        not isinstance(compiled, dict)
        or set(compiled)
        != {
            "schema_version",
            "evaluator_version",
            "metadata",
            "source_filters",
            "selections",
            "condition",
        }
        or type(compiled["schema_version"]) is not int
        or compiled["schema_version"] != 1
        or compiled["evaluator_version"] != EVALUATOR_VERSION
        or not isinstance(compiled["metadata"], dict)
        or not isinstance(compiled["source_filters"], list)
        or not 1 <= len(compiled["source_filters"]) <= 8
        or not isinstance(compiled["selections"], dict)
        or not 1 <= len(compiled["selections"]) <= MAX_SELECTIONS
    ):
        _invalid()
    filters = [_predicate(item) for item in compiled["source_filters"]]
    if (
        filters[0]["field"] != "source.type"
        or filters[0]["operator"] != "equals"
        or len(filters[0]["values"]) != 1
        or filters[0]["values"][0]
        not in {
            "windows_process",
            "windows_auth",
            "linux_auth",
            "nginx",
            "firewall",
            "generic_json",
        }
        or any(item["operator"] != "equals" for item in filters)
    ):
        _invalid()
    predicates = total_values = 0
    for name, alternatives in compiled["selections"].items():
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 64
            or not isinstance(alternatives, list)
            or not 1 <= len(alternatives) <= MAX_SELECTIONS
        ):
            _invalid()
        for terms in alternatives:
            if not isinstance(terms, list) or not terms:
                _invalid()
            for term in terms:
                predicate = _predicate(term)
                predicates += 1
                total_values += len(predicate["values"])
                if predicates > MAX_PREDICATES or total_values > MAX_VALUES:
                    _invalid()
    _condition(compiled["condition"], set(compiled["selections"]), [0])


def _field(document: dict[str, Any], path: str) -> str | int | None:
    parent, name = path.split(".", 1)
    if parent == "user" and name.startswith("target."):
        user = document.get("user")
        source = user.get("target") if isinstance(user, dict) else None
        name = name.removeprefix("target.")
    else:
        source = document.get(parent)
    value = source.get(name) if isinstance(source, dict) else None
    if path in INTEGER_FIELDS:
        lower, upper = INTEGER_BOUNDS[path]
        return value if type(value) is int and lower <= value <= upper else None
    return (
        value
        if isinstance(value, str) and 1 <= len(value) <= MAX_VALUE_LENGTH and "\x00" not in value
        else None
    )


def _matches(term: dict[str, Any], document: dict[str, Any]) -> bool:
    value = _field(document, term["field"])
    if value is None:
        return False
    if type(value) is int:
        return value in term["values"]
    assert isinstance(value, str)
    actual = value.casefold()
    for expected in term["values"]:
        target = expected.casefold()
        if (
            (term["operator"] == "equals" and actual == target)
            or (term["operator"] == "contains" and target in actual)
            or (term["operator"] == "startswith" and actual.startswith(target))
            or (term["operator"] == "endswith" and actual.endswith(target))
        ):
            return True
    return False


def _truth(node: dict[str, Any], selections: dict[str, bool]) -> bool:
    match node["kind"]:
        case "selection":
            return selections[node["name"]]
        case "not":
            return not _truth(node["item"], selections)
        case "and":
            return all(_truth(child, selections) for child in node["items"])
        case "or":
            return any(_truth(child, selections) for child in node["items"])
    _invalid()


def evaluate(
    compiled: CompiledRule | dict[str, Any], document: dict[str, Any]
) -> dict[str, Any] | None:
    """Match source facts without I/O; a missing field fails its selection.

    Boolean NOT negates that false selection, so NOT of a missing-field selection
    is true. No existence or null semantics are inferred beyond this rule.
    """
    definition = compiled.as_dict() if isinstance(compiled, CompiledRule) else compiled
    _validate(definition)
    if not all(_matches(term, document) for term in definition["source_filters"]):
        return None
    selections: dict[str, bool] = {}
    matched_fields: dict[str, str | int] = {}
    for name, alternatives in definition["selections"].items():
        matching = [
            terms for terms in alternatives if all(_matches(term, document) for term in terms)
        ]
        selections[name] = bool(matching)
        for terms in matching:
            for term in terms:
                value = _field(document, term["field"])
                assert value is not None
                matched_fields[term["field"]] = value
    if not _truth(definition["condition"], selections):
        return None
    return {
        "code": "sigma_selection_match",
        "summary": "Zdarzenie spełnia obsługiwany warunek reguły Sigma; wymaga oceny analityka.",
        "matched_fields": matched_fields,
        "matched_selections": sorted(name for name, matched in selections.items() if matched),
        "condition": deepcopy(definition["condition"]),
    }
