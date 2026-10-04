"""Resource-bounded safe YAML with explicit subset restrictions."""

from collections.abc import Hashable
from typing import Any, Never

import yaml
from yaml.events import (
    AliasEvent,
    DocumentStartEvent,
    MappingEndEvent,
    MappingStartEvent,
    ScalarEvent,
    SequenceEndEvent,
    SequenceStartEvent,
)
from yaml.nodes import MappingNode

MAX_YAML_BYTES = 65536
MAX_NODES = 2048
MAX_YAML_DEPTH = 12


class SigmaValidationError(ValueError):
    """A safe, structured diagnostic that never includes the imported YAML."""

    def __init__(self, code: str, message: str, path: str = "") -> None:
        self.code, self.message, self.path = code, message, path
        super().__init__(message)


def _reject(code: str, message: str, path: str = "") -> Never:
    raise SigmaValidationError(code, message, path)


class _StrictLoader(yaml.SafeLoader):
    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        result: dict[Hashable, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key == "<<":
                _reject("yaml_key", "YAML keys must be strings and merge keys are unsupported.")
            if key in result:
                _reject("yaml_duplicate_key", "Duplicate YAML keys are unsupported.")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


# Copy the resolver table: modifying SafeLoader globally would affect other users.
_StrictLoader.yaml_implicit_resolvers = {
    character: [
        (tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:timestamp"
    ]
    for character, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def parse_yaml(text: str) -> dict[str, Any]:
    if not isinstance(text, str):
        _reject("yaml_type", "A YAML string is required.")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError:
        _reject("yaml_encoding", "YAML must be valid UTF-8 text.")
    if not text.strip() or size > MAX_YAML_BYTES or "\x00" in text:
        _reject("yaml_size", "YAML must be nonempty, NUL-free and at most 65536 UTF-8 bytes.")
    try:
        documents = nodes = depth = 0
        for item in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(item, DocumentStartEvent):
                documents += 1
                if documents > 1 or item.version is not None or item.tags:
                    _reject(
                        "yaml_document", "Only one YAML document without directives is supported."
                    )
            if isinstance(item, AliasEvent):
                _reject("yaml_alias", "YAML aliases are unsupported.")
            if isinstance(item, (MappingStartEvent, SequenceStartEvent, ScalarEvent)):
                nodes += 1
                if item.anchor is not None or item.tag is not None:
                    _reject("yaml_tag", "YAML anchors and explicit tags are unsupported.")
                if nodes > MAX_NODES:
                    _reject("yaml_nodes", "YAML exceeds the supported node count.")
            if isinstance(item, (MappingStartEvent, SequenceStartEvent)):
                depth += 1
                if depth > MAX_YAML_DEPTH:
                    _reject("yaml_depth", "YAML exceeds the supported nesting depth.")
            elif isinstance(item, (MappingEndEvent, SequenceEndEvent)):
                depth -= 1
        document = yaml.load(text, Loader=_StrictLoader)
    except yaml.YAMLError:
        _reject("yaml_syntax", "Invalid YAML syntax.")
    if not isinstance(document, dict):
        _reject("rule_object", "A Sigma rule must be a YAML mapping.")
    return document
