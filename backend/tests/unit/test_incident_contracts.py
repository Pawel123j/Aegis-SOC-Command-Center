"""Case lifecycle, bounded Unicode input and immutable scoring contracts."""

from itertools import product
from typing import Any
from unittest.mock import Mock
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.core.permissions import Role
from app.modules.incidents import service
from app.modules.incidents.models import Incident
from app.modules.incidents.schemas import IncidentCreate, IncidentPatch, NoteCreate
from app.modules.users.models import User

STATUSES = ("new", "investigating", "contained", "resolved", "closed")
REPEATED_ALERT_ID = uuid4()
ALLOWED = {
    ("new", "investigating"),
    ("new", "resolved"),
    ("investigating", "contained"),
    ("investigating", "resolved"),
    ("contained", "investigating"),
    ("contained", "resolved"),
    ("resolved", "closed"),
    ("resolved", "investigating"),
    ("closed", "investigating"),
}


@pytest.mark.parametrize(("before", "after"), list(product(STATUSES, repeat=2)))
def test_all_case_status_pairs_respect_the_reviewed_lifecycle(
    before: str,
    after: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incident = Incident(id=uuid4(), status=before, title="Case", owner_id=None)
    actor = User(id=uuid4(), username="supervisor", role=Role.SOC_MANAGER)
    history: list[str] = []

    def record(*args: Any, **kwargs: Any) -> None:
        history.append(args[2])

    monkeypatch.setattr(service, "record_change", record)
    data = IncidentPatch(status=after, status_reason="Evidence reviewed")
    if (before, after) in ALLOWED:
        service.patch_incident(Mock(spec=Session), incident, data, request_id="test", actor=actor)
        assert incident.status == after and history == ["status_changed"]
    else:
        with pytest.raises(ApiError) as rejected:
            service.patch_incident(
                Mock(spec=Session), incident, data, request_id="test", actor=actor
            )
        assert rejected.value.status == 409
        assert incident.status == before and history == []


@pytest.mark.parametrize(
    "payload",
    [
        {"title": "  "},
        {"title": "Bad\x00text"},
        {"title": "Bad\ntext"},
        {"title": "Case", "tags": ["SOC", "soc"]},
        {"title": "Case", "tags": ["x" * 65]},
        {"title": "Case", "tags": [str(number) for number in range(21)]},
        {"title": "Case", "risk_score": 99},
        {"title": "Case", "confidence": 99},
        {"title": "Case", "alert_ids": [str(REPEATED_ALERT_ID), str(REPEATED_ALERT_ID)]},
    ],
)
def test_case_create_rejects_invalid_or_fake_assessment_fields(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        IncidentCreate.model_validate(payload)


@pytest.mark.parametrize(
    "payload", [{}, {"description": None}, {"status_reason": "Reviewed"}, {"risk_score": 10}]
)
def test_patch_requires_real_non_null_changes(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        IncidentPatch.model_validate(payload)


def test_unicode_text_and_tags_are_plain_text_and_bounded() -> None:
    data = IncidentCreate(
        title="  żółć <script>alert(1)</script> ", tags=[" SOC ", "żółć"], description="\nContext\n"
    )
    assert data.title == "żółć <script>alert(1)</script>"
    assert data.tags == ["soc", "żółć"] and data.description == "Context"
    assert NoteCreate(body="\n Analyst\n note\t ").body == "Analyst\n note"
    with pytest.raises(ValidationError):
        NoteCreate(body="  ")
