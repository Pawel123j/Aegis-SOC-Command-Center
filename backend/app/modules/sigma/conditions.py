"""Bounded Boolean parser: no evaluation of executable source expressions."""

from typing import Any

from app.modules.sigma.yaml_support import _reject

MAX_CONDITION_LENGTH = 1024
MAX_CONDITION_TOKENS = 128
MAX_CONDITION_DEPTH = 16


class ConditionParser:
    def __init__(self, text: str, names: set[str]) -> None:
        if not text.strip() or len(text) > MAX_CONDITION_LENGTH:
            _reject(
                "condition_length", "Condition exceeds the supported length.", "detection.condition"
            )
        self.tokens: list[str] = []
        position = 0
        while position < len(text):
            character = text[position]
            if character.isspace():
                position += 1
                continue
            if character in "()":
                token = character
                position += 1
            elif character.isascii() and (character.isalpha() or character == "_"):
                start = position
                while (
                    position < len(text)
                    and text[position].isascii()
                    and (text[position].isalnum() or text[position] == "_")
                ):
                    position += 1
                token = text[start:position]
                if len(token) > 64:
                    _reject(
                        "condition_identifier",
                        "Condition identifiers exceed the supported length.",
                        "detection.condition",
                    )
            else:
                _reject(
                    "unsupported_condition",
                    "Conditions support identifiers, parentheses and AND/OR/NOT only.",
                    "detection.condition",
                )
            self.tokens.append(token)
            if len(self.tokens) > MAX_CONDITION_TOKENS:
                _reject(
                    "condition_tokens",
                    "Condition exceeds the supported token count.",
                    "detection.condition",
                )
        self.position, self.names = 0, names

    def _peek(self, keyword: str) -> bool:
        return self.position < len(self.tokens) and self.tokens[self.position].casefold() == keyword

    def _logical(self, operator: str, depth: int) -> dict[str, Any]:
        nested = self._unary if operator == "and" else lambda depth: self._logical("and", depth)
        items = [nested(depth)]
        while self._peek(operator):
            self.position += 1
            items.append(nested(depth))
        return items[0] if len(items) == 1 else {"kind": operator, "items": items}

    def _unary(self, depth: int) -> dict[str, Any]:
        if depth > MAX_CONDITION_DEPTH:
            _reject(
                "condition_depth",
                "Condition exceeds the supported nesting depth.",
                "detection.condition",
            )
        if self._peek("not"):
            self.position += 1
            return {"kind": "not", "item": self._unary(depth + 1)}
        if self._peek("("):
            self.position += 1
            node = self._logical("or", depth + 1)
            if not self._peek(")"):
                _reject(
                    "condition_syntax",
                    "Condition parentheses are unbalanced.",
                    "detection.condition",
                )
            self.position += 1
            return node
        if self.position >= len(self.tokens) or self.tokens[self.position] not in self.names:
            _reject(
                "condition_selection",
                "Condition references an unknown selection or lacks an operand.",
                "detection.condition",
            )
        name = self.tokens[self.position]
        self.position += 1
        return {"kind": "selection", "name": name}

    def parse(self) -> dict[str, Any]:
        node = self._logical("or", 1)
        if self.position != len(self.tokens):
            _reject(
                "condition_syntax", "Unexpected trailing condition token.", "detection.condition"
            )
        pending = [(node, 1)]
        count = 0
        while pending:
            current, depth = pending.pop()
            count += 1
            if depth > MAX_CONDITION_DEPTH or count > MAX_CONDITION_TOKENS:
                _reject(
                    "condition_depth",
                    "Compiled condition exceeds the supported budget.",
                    "detection.condition",
                )
            if current["kind"] == "not":
                pending.append((current["item"], depth + 1))
            elif current["kind"] in {"and", "or"}:
                pending.extend((item, depth + 1) for item in current["items"])
        return node
