"""Observable temporal semantics: counts, ordering, boundaries and minimal proof."""

import random
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.modules.correlation.builtin import rule_definition
from app.modules.correlation.contracts import Condition, Pattern, Stage
from app.modules.correlation.engine import condition_matches, detection_key, evaluate_anchor
from app.modules.normalization.schemas import NormalizedSecurityEvent

BASE = datetime(2026, 10, 1, 12, tzinfo=UTC)


def event(
    identifier: int, second: int, *, outcome: str = "failure", **values: Any
) -> NormalizedSecurityEvent:
    document = {
        "event_id": str(UUID(int=identifier)),
        "source_id": str(UUID(int=100)),
        "dataset_id": str(UUID(int=101)),
        "run_id": str(UUID(int=0)),
        "mode": "live",
        "timestamp": (BASE + timedelta(seconds=second)).isoformat(),
        "received_at": BASE.isoformat(),
        "processed_at": BASE.isoformat(),
        "source": {"name": "test", "type": "generic_json", "ip": "192.0.2.1"},
        "host": {"id": "host-A"},
        "user": {"name": "alice", "realm": "LAB"},
        "event": {"category": "authentication", "outcome": outcome},
        "raw_event": {"message": "fixture"},
        "raw_sha256": "a" * 64,
    }
    document.update(values)
    return NormalizedSecurityEvent.model_validate(document)


def sequence() -> list[NormalizedSecurityEvent]:
    return [*[event(index + 1, index) for index in range(5)], event(6, 5, outcome="success")]


@pytest.mark.parametrize("count,matched", [(4, False), (5, True), (6, True)])
def test_threshold_counts_distinct_events_with_minimal_proof(count: int, matched: bool) -> None:
    rule = rule_definition("repeated_authentication_failures")
    records = [event(index + 1, index) for index in range(count)]
    result = evaluate_anchor(rule, records[-1], records)
    assert bool(result) is matched
    if result:
        assert len(result["event_ids"]) == 5
        assert result["event_ids"] == [str(row.event_id) for row in records[-5:]]


@pytest.mark.parametrize("end,matched", [(599, True), (600, True), (601, False)])
def test_whole_sequence_window_boundary(end: int, matched: bool) -> None:
    records = [*[event(index + 1, index) for index in range(5)], event(6, end, outcome="success")]
    result = evaluate_anchor(
        rule_definition("possible_bruteforce_compromise"), records[-1], records
    )
    assert bool(result) is matched


def test_permuted_complete_set_has_identical_proof_and_key() -> None:
    records = sequence()
    rule = rule_definition("possible_bruteforce_compromise")
    expected = evaluate_anchor(rule, records[-1], records)
    assert expected
    expected_key = detection_key(rule, expected, "live")
    for seed in range(20):
        permuted = list(records)
        random.Random(seed).shuffle(permuted)
        result = evaluate_anchor(rule, records[-1], permuted)
        assert result == expected
        assert detection_key(rule, result, "live") == expected_key


@pytest.mark.parametrize("success_second", [0, -1, 4])
def test_sequence_needs_strict_event_time_order(success_second: int) -> None:
    records = [
        *[event(index + 1, index) for index in range(5)],
        event(6, success_second, outcome="success"),
    ]
    assert (
        evaluate_anchor(rule_definition("possible_bruteforce_compromise"), records[-1], records)
        is None
    )


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("source", {"name": "other", "type": "generic_json", "ip": "192.0.2.2"}),
        ("host", {"id": "host-B"}),
        ("user", {"name": "bob", "realm": "LAB"}),
    ],
)
def test_nat_same_ip_does_not_replace_other_required_keys(
    field: str, replacement: dict[str, str]
) -> None:
    records = sequence()
    records[-1] = records[-1].model_copy(
        update={field: type(getattr(records[-1], field)).model_validate(replacement)}
    )
    assert (
        evaluate_anchor(rule_definition("possible_bruteforce_compromise"), records[-1], records)
        is None
    )


def test_replay_dataset_and_run_are_separate_namespaces() -> None:
    records = sequence()
    records[-1] = records[-1].model_copy(update={"mode": "replay", "run_id": UUID(int=9)})
    assert (
        evaluate_anchor(rule_definition("possible_bruteforce_compromise"), records[-1], records)
        is None
    )


@pytest.mark.parametrize("process_name", ["powershell.exe", "pwsh", "PWSH.EXE"])
def test_or_process_branches_and_explicit_outbound_action(process_name: str) -> None:
    records = [
        event(
            1, 0, event={"category": "process"}, process={"name": process_name, "entity_id": "p1"}
        ),
        event(
            2,
            1,
            event={"category": "network", "action": "outbound_connection"},
            process={"entity_id": "p1"},
        ),
    ]
    assert evaluate_anchor(rule_definition("powershell_then_outbound"), records[-1], records)


@pytest.mark.parametrize(
    "direction,matched", [(None, False), ("inbound", False), ("outbound", True)]
)
def test_generic_connection_requires_outbound_direction(
    direction: str | None, matched: bool
) -> None:
    records = [
        event(1, 0, event={"category": "process"}, process={"name": "pwsh", "entity_id": "p1"}),
        event(
            2,
            1,
            event={"category": "network", "action": "connection"},
            process={"entity_id": "p1"},
            extensions={"direction": direction} if direction else {},
        ),
    ]
    assert (
        bool(evaluate_anchor(rule_definition("powershell_then_outbound"), records[-1], records))
        is matched
    )


def test_full_chain_requires_all_five_stages_and_stable_process_link() -> None:
    records = sequence() + [
        event(
            7,
            6,
            event={"category": "process"},
            process={"name": "powershell.exe", "entity_id": "p1"},
        ),
        event(
            8,
            7,
            event={"category": "iam", "code": "4732"},
            extensions={"group": {"id": "S-1-5-32-544"}},
        ),
        event(
            9,
            8,
            event={"category": "network", "action": "outbound_connection"},
            process={"entity_id": "p1"},
        ),
    ]
    result = evaluate_anchor(
        rule_definition("possible_multi_stage_compromise"), records[-1], records
    )
    assert result and len(result["event_ids"]) == 9 and len(result["reason"]["stages"]) == 5
    assert result["reason"]["assessment"] == "potential_activity_requires_analyst_review"


@pytest.mark.parametrize(
    "operator,value,matched",
    [("contains", "encoded", True), ("endswith", ".exe", True), ("equals", "other", False)],
)
def test_native_leaf_operations(operator: str, value: str, matched: bool) -> None:
    condition = Condition.model_validate(
        {"field": "process.name", "operator": operator, "value": value}
    )
    assert condition_matches(condition, {"process": {"name": "encoded.exe"}}) is matched
    assert not condition_matches(condition, {})


def test_pattern_cannot_promise_more_than_100_evidence_events() -> None:
    stages = [
        Stage(
            name=str(index),
            count=20,
            condition=Condition(field="event.type", operator="equals", value="start"),
        )
        for index in range(6)
    ]
    with pytest.raises(ValidationError):
        Pattern(kind="sequence", window_seconds=600, group_by=["same_host"], stages=stages)
