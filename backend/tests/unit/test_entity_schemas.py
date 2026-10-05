"""Explicit scope, UTC windows and bounded mutation inputs."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.modules.entities.schemas import BackfillInput, EntityFilters

NOW = datetime(2026, 10, 4, tzinfo=UTC)


def test_default_window_is_thirty_days_and_does_not_change_scope() -> None:
    filters = EntityFilters()
    assert filters.window(NOW) == (NOW - timedelta(days=30), NOW)
    assert filters.mode == "live" and filters.dataset_id is filters.run_id is None


@pytest.mark.parametrize(
    "values",
    [
        {"mode": "live", "dataset_id": uuid4()},
        {"mode": "live", "run_id": uuid4()},
        {"mode": "replay"},
        {"mode": "replay", "dataset_id": uuid4(), "run_id": UUID(int=0)},
        {"mode": "replay", "dataset_id": UUID(int=0), "run_id": uuid4()},
        {"from": "2026-10-01T00:00:00"},
        {"to": "2026-10-01T00:00:00+02:00"},
        {"q": " "},
        {"q": "a\x00b"},
        {"q": "a\nb"},
        {"q": "x" * 129},
        {"limit": 0},
        {"limit": 101},
        {"kind": "account"},
        {"cursor": "x" * 4097},
        {"unused": "hidden filter"},
    ],
)
def test_invalid_filters_fail_closed(values: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        EntityFilters.model_validate(values)


@pytest.mark.parametrize(
    "values",
    [
        {"from": NOW, "to": NOW},
        {"to": NOW + timedelta(seconds=1)},
        {"from": NOW - timedelta(days=367)},
    ],
)
def test_invalid_windows_rejected(values: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        EntityFilters.model_validate(values).window(NOW)


@pytest.mark.parametrize("limit", [0, 101, True, "2", 1.5])
def test_backfill_requires_bounded_strict_integer(limit: object) -> None:
    with pytest.raises(ValidationError):
        BackfillInput.model_validate({"limit": limit})


def test_exact_replay_and_maximum_window_accepted() -> None:
    filters = EntityFilters(
        mode="replay",
        dataset_id=uuid4(),
        run_id=uuid4(),
        from_=NOW - timedelta(days=366),
        to=NOW,
        limit=100,
    )
    assert filters.window(NOW) == (NOW - timedelta(days=366), NOW)
