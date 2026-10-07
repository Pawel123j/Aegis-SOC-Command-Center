"""Complete UTC windows, honest cold starts, feature cohorts and deterministic scores."""

from datetime import UTC, date, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError
from test_entity_identity import document

from app.modules.entities.identity import extract_entity_descriptors
from app.modules.normalization.schemas import NormalizedSecurityEvent
from app.modules.ueba.schemas import UebaEntity, UebaFilters, UebaScope
from app.modules.ueba.statistics import VerifiedEvent, report

START = datetime(2026, 9, 1, tzinfo=UTC)
OBSERVED = START + timedelta(days=28)
END = OBSERVED + timedelta(days=1)
NOW = END + timedelta(days=1)


def event(number: int, day: int = 0, hour: int = 9, **values: Any) -> VerifiedEvent:
    data = document(
        event_id=str(UUID(int=number + 1)),
        timestamp=(START + timedelta(days=day, hours=hour)).isoformat(),
        source={"name": "source", "type": "generic_json", "ip": "192.0.2.1"},
        user={"name": "alice"},
        event={"category": "authentication", "type": "start", "outcome": "success"},
    )
    data.update(values)
    parsed = NormalizedSecurityEvent.model_validate(data)
    return VerifiedEvent(parsed, f"{number + 1:064x}", extract_entity_descriptors(parsed))


def baseline(**values: Any) -> list[VerifiedEvent]:
    return [event(i, day=i // 3, **values) for i in range(21)]


def evaluate(items: list[VerifiedEvent], *, role: str = "host", pending: int = 0) -> Any:
    identity = next(item for item in items[0].descriptors if item.role == role)
    return report(
        UebaEntity(
            id=identity.entity_id,
            kind=identity.entity_type,
            label=identity.label,
            identity_basis=identity.identity_strength,
        ),
        UebaScope(mode="live", dataset_id=None, run_id=None),
        items,
        START,
        OBSERVED,
        END,
        pending,
        cross_host=identity.identity_strength == "source_scoped" and role != "host",
        as_of=NOW,
    )


def indicator(result: Any, name: str) -> Any:
    return next(item for item in result.indicators if item.id == name)


def test_default_observation_is_yesterday_utc_with_28_prior_days() -> None:
    assert UebaFilters().window(NOW) == (START + timedelta(days=1), END, NOW)
    offset = datetime.fromisoformat("2026-10-01T00:30:00+02:00")
    assert UebaFilters().window(offset)[1].date() == date(2026, 9, 29)


@pytest.mark.parametrize("day", ["2026-10-01", "2026-10-02", "1969-01-01", "1970-01-28"])
def test_day_requires_completed_window(day: str) -> None:
    with pytest.raises(ValueError):
        UebaFilters(day=date.fromisoformat(day)).window(NOW)


@pytest.mark.parametrize(
    "values",
    [
        {"mode": "replay"},
        {"mode": "replay", "dataset_id": UUID(int=1)},
        {"mode": "replay", "dataset_id": UUID(int=1), "run_id": UUID(int=0)},
        {"dataset_id": UUID(int=1)},
        {"run_id": UUID(int=1)},
        {"from": "2026-01-01"},
    ],
)
def test_scope_is_explicit(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        UebaFilters.model_validate(values)


def test_novel_hour_and_ip_show_evidence_and_max_fixed_weight() -> None:
    result = evaluate(
        baseline()
        + [
            event(
                100, 28, 2, source={"name": "source", "type": "generic_json", "ip": "2001:db8::1"}
            )
        ]
    )
    assert result.status == "ready" and result.score == 40
    hours = indicator(result, "unusual_login_hour")
    assert hours.status == "anomaly" and hours.baseline_values == ["09:00 UTC"]
    assert hours.observed_values == ["02:00 UTC"] and hours.evidence_total == 1
    assert hours.evidence[0].event_id == UUID(int=101)
    assert indicator(result, "new_login_ip").observed_values == ["2001:db8::1"]


def test_known_successful_login_is_normal_and_admin_claim_is_unsupported() -> None:
    result = evaluate(baseline() + [event(100, 28)])
    assert result.score == 0
    assert indicator(result, "new_login_ip").status == "normal"
    assert indicator(result, "admin_account_use").status == "unsupported"
    assert indicator(result, "new_login_host").status == "unsupported"


@pytest.mark.parametrize("case", ["events", "days", "quality", "pending"])
def test_cold_or_pending_never_asserts_anomalies(case: str) -> None:
    items = baseline()
    if case == "events":
        items = items[:19]
    elif case == "days":
        items = [event(i, day=i % 6) for i in range(30)]
    elif case == "quality":
        items = baseline(quality=["inferred_year"])
    result = evaluate(
        items + [event(100 + i, 28, 1) for i in range(30)], pending=1 if case == "pending" else 0
    )
    assert result.status == ("index_pending" if case == "pending" else "cold_start")
    assert result.score is None
    assert all(
        item.status != "anomaly" and item.score == 0 and not item.evidence
        for item in result.indicators
    )


@pytest.mark.parametrize(
    "flag", ["timestamp_from_received_at", "missing_source_timestamp", "inferred_year"]
)
def test_uncertain_timestamps_are_excluded_from_both_windows(flag: str) -> None:
    result = evaluate(
        baseline() + [event(100, 5, quality=[flag]), event(101, 28, 2, quality=[flag])]
    )
    assert result.baseline.event_count == 22 and result.baseline.eligible_events == 21
    assert (
        result.baseline.excluded_timestamp_events
        == result.observation.excluded_timestamp_events
        == 1
    )
    assert result.observation.eligible_events == 0 and result.score == 0


def test_windows_target_receives_login_actor_does_not() -> None:
    account = {"id": "S-1-5-21-1-2-3-1001", "name": "alice"}
    values = {
        "host": {"name": "host", "os": "Windows"},
        "user": {"name": "SYSTEM", "target": account},
    }
    items = baseline(**values) + [event(100, 28, 1, **values)]
    assert indicator(evaluate(items, role="target"), "unusual_login_hour").status == "anomaly"
    assert indicator(evaluate(items, role="actor"), "unusual_login_hour").baseline_event_count == 0


def test_full_sid_observes_new_reporting_host_without_merging_weak_identities() -> None:
    account = {"id": "S-1-5-21-1-2-3-1001", "name": "alice"}
    items = baseline(host={"name": "old", "os": "Windows"}, user=account)
    items.append(event(100, 28, host={"name": "new", "os": "Windows"}, user=account))
    result = indicator(evaluate(items, role="actor"), "new_login_host")
    assert result.status == "anomaly" and result.score == 45
    weak = indicator(evaluate(baseline(), role="actor"), "new_login_host")
    assert weak.status == "unsupported"


@pytest.mark.parametrize("outcome", ["success", "failure"])
@pytest.mark.parametrize("target", [{}, {"name": "-"}, {"id": "S-1-0-0"}])
def test_windows_missing_login_target_never_falls_back_to_subject(
    outcome: str, target: dict[str, str]
) -> None:
    values = {
        "source": {"name": "windows", "type": "windows_auth", "ip": "192.0.2.1"},
        "host": {"name": "server", "os": "windows"},
        "user": {"id": "S-1-5-18", "name": "SYSTEM", "target": target},
        "event": {
            "category": "authentication",
            "type": "start",
            "action": "windows_logon",
            "code": "4624" if outcome == "success" else "4625",
            "outcome": outcome,
        },
    }
    items = baseline(**values) + [event(100 + i, 28, 1, **values) for i in range(5)]
    actor = evaluate(items, role="actor")
    for name in ("unusual_login_hour", "new_login_ip", "failed_login_burst"):
        item = indicator(actor, name)
        assert item.baseline_event_count == item.observed_count == 0
        assert item.status != "anomaly"
    host = evaluate(items)
    name = "unusual_login_hour" if outcome == "success" else "failed_login_burst"
    assert indicator(host, name).baseline_event_count == 21
    assert indicator(host, name).observed_count == 5


@pytest.mark.parametrize("outcome", ["success", "failure"])
def test_su_with_unknown_target_never_counts_as_actor_login(outcome: str) -> None:
    values = {
        "source": {"name": "linux", "type": "linux_auth"},
        "host": {"name": "server", "os": "linux"},
        "user": {"name": "alice", "target": {"name": "-"}},
        "event": {
            "category": "authentication",
            "type": "start",
            "action": "su_session",
            "outcome": outcome,
        },
    }
    items = baseline(**values) + [event(100, 28, 1, **values)]
    actor = evaluate(items, role="actor")
    name = "unusual_login_hour" if outcome == "success" else "failed_login_burst"
    assert indicator(actor, name).baseline_event_count == 0
    assert indicator(actor, name).observed_count == 0
    assert indicator(evaluate(items), name).baseline_event_count == 21


@pytest.mark.parametrize("event_type", ["end", "unknown", "info"])
def test_session_close_and_nonlogin_authentication_do_not_count(event_type: str) -> None:
    result = evaluate(
        baseline()
        + [
            event(
                100,
                28,
                2,
                event={"category": "authentication", "type": event_type, "outcome": "success"},
            )
        ]
    )
    assert indicator(result, "unusual_login_hour").observed_count == 0


def test_failed_logins_never_train_successful_login_novelty() -> None:
    result = evaluate(
        baseline(event={"category": "authentication", "type": "start", "outcome": "failure"})
        + [event(100, 28, 2)]
    )
    assert result.status == "ready"
    assert indicator(result, "unusual_login_hour").status == "insufficient_data"


def test_sparse_ip_facts_do_not_create_confident_novelty() -> None:
    items = baseline(source={"name": "source", "type": "generic_json"})
    items[0] = event(0)
    result = evaluate(
        items
        + [event(100, 28, source={"name": "source", "type": "generic_json", "ip": "192.0.2.2"})]
    )
    ip = indicator(result, "new_login_ip")
    assert ip.status == "insufficient_data" and ip.baseline_event_count == 1


def test_new_tool_uses_exact_basename_and_excludes_denied_processes() -> None:
    process = {"category": "process", "type": "start", "outcome": "success"}
    items = baseline(event=process, process={"executable": "/usr/bin/python"})
    result = evaluate(
        items + [event(100, 28, event=process, process={"executable": "/usr/bin/sudo"})]
    )
    assert indicator(result, "first_admin_tool").status == "anomaly" and result.score == 50
    denied = {**process, "outcome": "failure"}
    result = evaluate(
        items + [event(100, 28, event=denied, process={"executable": "/usr/bin/sudo"})]
    )
    assert indicator(result, "first_admin_tool").observed_count == 0


@pytest.mark.parametrize("name", ["not-sudo", "SUDO", "sudo.exe", r"C:\sudo", "sudo-backup"])
def test_posix_similar_tool_names_are_not_aliases(name: str) -> None:
    process = {"category": "process", "type": "start"}
    result = evaluate(
        baseline(event=process, process={"name": "python"})
        + [event(100, 28, event=process, process={"name": name})]
    )
    assert indicator(result, "first_admin_tool").status == "normal"


def test_windows_tool_basename_is_case_insensitive_and_executable_takes_precedence() -> None:
    process = {"category": "process", "type": "start"}
    host = {"name": "host", "os": "Windows"}
    items = baseline(event=process, process={"name": "explorer.exe"}, host=host)
    result = evaluate(
        items
        + [
            event(
                100,
                28,
                event=process,
                process={"executable": r"C:\Windows\POWERSHELL.EXE"},
                host=host,
            )
        ]
    )
    assert indicator(result, "first_admin_tool").observed_values == ["powershell.exe"]
    result = evaluate(
        items
        + [
            event(
                100,
                28,
                event=process,
                process={"executable": "other.exe", "name": "powershell.exe"},
                host=host,
            )
        ]
    )
    assert indicator(result, "first_admin_tool").status == "normal"


@pytest.mark.parametrize("amount,anomaly", [(4, False), (5, True)])
def test_failed_login_threshold_includes_zero_days_and_exact_boundary(
    amount: int, anomaly: bool
) -> None:
    failures = [
        event(
            100 + i, 28, event={"category": "authentication", "type": "start", "outcome": "failure"}
        )
        for i in range(amount)
    ]
    item = indicator(evaluate(baseline() + failures), "failed_login_burst")
    assert item.threshold == 5 and item.daily_mean == item.daily_stddev == 0
    assert (item.status == "anomaly") == anomaly


def test_activity_uses_28_bins_population_stddev_deduplicates_and_bounds_evidence() -> None:
    originals = baseline() + [event(100 + i, 28, 9) for i in range(31)]
    result = evaluate(list(reversed(originals)) + originals)
    activity = indicator(result, "activity_burst")
    assert result.baseline.eligible_events == 21 and result.observation.eligible_events == 31
    assert activity.daily_mean == 0.75
    assert activity.daily_stddev == pytest.approx(1.299038105676658)
    assert (
        activity.threshold == 20 and activity.evidence_total == 31 and len(activity.evidence) == 25
    )
    assert [item.event_id.int for item in activity.evidence] == list(range(101, 126))


def test_strict_baseline_and_observation_boundaries() -> None:
    items = baseline() + [event(100, -1, 23), event(101, 28, 0), event(102, 29, 0)]
    result = evaluate(items)
    assert result.baseline.event_count == 21 and result.observation.event_count == 1
    assert indicator(result, "unusual_login_hour").evidence[0].event_id == UUID(int=102)


@pytest.mark.parametrize("role", ["source", "process"])
def test_unsupported_entity_kinds_have_no_score_or_indicators(role: str) -> None:
    result = evaluate(baseline(process={"name": "sudo"}), role=role)
    assert result.status == "unsupported" and result.score is None and result.indicators == []
