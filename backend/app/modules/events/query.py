"""Small typed query language. User text never becomes a SQL identifier or fragment."""

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from app.modules.normalization.schemas import canonical_ip


class QueryError(ValueError):
    """A bounded, deliberately unsupported or malformed expression."""


@dataclass(frozen=True)
class Field:
    column: str
    kind: Literal["text", "number", "ip", "uuid", "outcome", "severity", "mode"] = "text"


FIELDS = {
    "event_id": Field("event_id", "uuid"),
    "source_id": Field("source_id", "uuid"),
    "dataset_id": Field("dataset_id", "uuid"),
    "run_id": Field("run_id", "uuid"),
    "mode": Field("mode", "mode"),
    "source.name": Field("source_name"),
    "source.type": Field("source_type"),
    "source.ip": Field("source_ip", "ip"),
    "destination.ip": Field("destination_ip", "ip"),
    "source.port": Field("source_port", "number"),
    "destination.port": Field("destination_port", "number"),
    "user.id": Field("user_id"),
    "user.name": Field("user_name"),
    "user.realm": Field("user_realm"),
    "user.target.id": Field("user_target_id"),
    "user.target.name": Field("user_target_name"),
    "user.target.realm": Field("user_target_realm"),
    "host.id": Field("host_id"),
    "host.name": Field("host_name"),
    "process.name": Field("process_name"),
    "process.executable": Field("process_executable"),
    "process.command_line": Field("command_line"),
    "event.category": Field("event_category"),
    "event.type": Field("event_type"),
    "event.action": Field("event_action"),
    "event.outcome": Field("event_outcome", "outcome"),
    "event.severity": Field("event_severity", "severity"),
    "event.code": Field("event_code"),
    "network.protocol": Field("network_protocol"),
    "http.status_code": Field("http_status_code", "number"),
}
ALIASES = {
    "username": "user.name",
    "hostname": "host.name",
    "source_ip": "source.ip",
    "destination_ip": "destination.ip",
    "source_port": "source.port",
    "destination_port": "destination.port",
    "process_name": "process.name",
    "command_line": "process.command_line",
    "action": "event.action",
    "source_type": "source.type",
    "severity": "event.severity",
    "result": "event.outcome",
}
TOKEN = re.compile(
    r'\s*("(?:[^"\\\x00-\x1f]|\\.)*"|>=|<=|!=|=|>|<|\(|\)|[0-9]+|[A-Za-z_][A-Za-z0-9_.]*)'
)


@dataclass(frozen=True)
class Comparison:
    field: str
    operator: str
    value: str | int | None


@dataclass(frozen=True)
class Boolean:
    operator: Literal["AND", "OR"]
    left: "Expression"
    right: "Expression"


type Expression = Comparison | Boolean


def parse_query(text: str) -> Expression | None:
    if len(text) > 4096:
        raise QueryError("query_too_large")
    if not text.strip():
        return None
    tokens: list[str] = []
    position = 0
    while position < len(text):
        if not text[position:].strip():
            break
        match = TOKEN.match(text, position)
        if match is None:
            raise QueryError("invalid_query")
        tokens.append(match[1])
        position = match.end()
        if len(tokens) > 256:
            raise QueryError("query_too_complex")
    return _Parser(tokens).parse()


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.position = 0
        self.comparisons = 0

    def take(self) -> str:
        if self.position >= len(self.tokens):
            raise QueryError("invalid_query")
        value = self.tokens[self.position]
        self.position += 1
        return value

    def peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def parse(self) -> Expression:
        expression = self.boolean(0, "OR")
        if self.peek() is not None:
            raise QueryError("invalid_query")
        return expression

    def boolean(self, depth: int, operator: Literal["AND", "OR"]) -> Expression:
        left = self.boolean(depth, "AND") if operator == "OR" else self.atom(depth)
        while self.peek() == operator:
            self.take()
            right = self.boolean(depth, "AND") if operator == "OR" else self.atom(depth)
            left = Boolean(operator, left, right)
        return left

    def atom(self, depth: int) -> Expression:
        if depth > 12:
            raise QueryError("query_too_complex")
        if self.peek() == "(":
            self.take()
            expression = self.boolean(depth + 1, "OR")
            if self.take() != ")":
                raise QueryError("invalid_query")
            return expression
        original = self.take()
        name = ALIASES.get(original, original)
        field = FIELDS.get(name)
        if field is None:
            raise QueryError("unsupported_field")
        operator = self.take()
        if operator not in {"=", "!=", "<", "<=", ">", ">=", "CONTAINS"}:
            raise QueryError("unsupported_operator")
        token = self.take()
        if token == "null":
            value: str | int | None = None
            if operator not in {"=", "!="}:
                raise QueryError("invalid_null_comparison")
        elif field.kind == "number":
            if not token.isascii() or not token.isdigit():
                raise QueryError("invalid_numeric_value")
            value = int(token)
            maximum = 599 if name == "http.status_code" else 65535
            if value > maximum or operator == "CONTAINS":
                raise QueryError("invalid_numeric_value")
        else:
            if not token.startswith('"'):
                raise QueryError("quoted_string_required")
            try:
                value = json.loads(token)
                assert isinstance(value, str)
                if len(value) > 1024 or "\x00" in value:
                    raise ValueError
                value.encode("utf-8")
                if field.kind == "ip":
                    value = canonical_ip(ipaddress.ip_address(value))
                elif field.kind == "uuid":
                    value = str(UUID(value))
                elif field.kind == "outcome":
                    value = {"failed": "failure", "succeeded": "success"}.get(value, value)
                    if value not in {"success", "failure", "unknown"}:
                        raise ValueError
                elif field.kind == "severity":
                    if value not in {"informational", "low", "medium", "high", "critical"}:
                        raise ValueError
                elif field.kind == "mode" and value not in {"live", "replay"}:
                    raise ValueError
                if field.kind != "text" and operator not in {"=", "!="}:
                    raise ValueError
                if field.kind == "text" and operator not in {"=", "!=", "CONTAINS"}:
                    raise ValueError
            except (ValueError, AssertionError, UnicodeError) as error:
                raise QueryError("invalid_query_value") from error
        self.comparisons += 1
        if self.comparisons > 64:
            raise QueryError("query_too_complex")
        return Comparison(name, operator, value)


def compile_query(expression: Expression | None) -> tuple[str, dict[str, str]]:
    parameters: dict[str, str] = {}

    def visit(node: Expression) -> str:
        if isinstance(node, Boolean):
            return f"({visit(node.left)} {node.operator} {visit(node.right)})"
        field = FIELDS[node.field]
        if node.value is None:
            return f"is{'Not' if node.operator == '!=' else ''}Null({field.column})"
        key = f"q{len(parameters)}"
        parameters[f"param_{key}"] = str(node.value)
        data_type = (
            "UInt32" if field.kind == "number" else "UUID" if field.kind == "uuid" else "String"
        )
        parameter = "{" + key + ":" + data_type + "}"
        if node.operator == "CONTAINS":
            return f"positionUTF8({field.column}, {parameter}) > 0"
        return f"{field.column} {node.operator} {parameter}"

    return (visit(expression), parameters) if expression else ("1", {})
