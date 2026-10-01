"""The initial alert API accepts bounded filters and explicit status decisions."""

import pytest
from pydantic import ValidationError

from app.modules.alerts.schemas import AlertFilters, AlertPatch


@pytest.mark.parametrize(
    "values",
    [
        {"limit": 0},
        {"limit": 501},
        {"status": "unknown"},
        {"severity": "urgent"},
        {"mode": "unknown"},
        {"source_id": "bad"},
        {"cursor": ""},
        {"cursor": "x" * 4097},
        {"extra": 1},
    ],
)
def test_invalid_alert_filters_are_rejected(values: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        AlertFilters.model_validate(values)


def test_url_integer_limit_and_empty_default_filters() -> None:
    assert AlertFilters.model_validate({"limit": "500"}).limit == 500
    assert AlertFilters().status is None


@pytest.mark.parametrize(
    "values", [{}, {"status": None}, {"status": "closed"}, {"status": "new", "severity": "high"}]
)
def test_invalid_status_decisions_are_rejected(values: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        AlertPatch.model_validate(values)
