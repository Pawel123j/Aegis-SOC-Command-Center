"""Closed language, truthful local actions and publication proof contracts."""

from copy import deepcopy
from typing import Any
from unittest.mock import Mock
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.errors import ApiError
from app.core.permissions import Permission
from app.modules.ingestion.schemas import canonical_json
from app.modules.soar.actions import execute_action
from app.modules.soar.models import PlaybookRevision
from app.modules.soar.schemas import Definition, RunInput, catalog, digest, required_permissions
from app.modules.soar.service import verified_revision


def definition(**values: Any) -> dict[str, Any]:
    return {"title": "Response", "steps": [{"id": "first", "action": "notify_analyst"}], **values}


@pytest.mark.parametrize(
    "action",
    [
        "shell",
        "exec",
        "block_ip",
        "isolate_host",
        "webhook",
        "__import__",
        "../notify_analyst",
        "http://127.0.0.1",
    ],
)
def test_executable_and_unknown_actions_are_rejected(action: str) -> None:
    with pytest.raises(ValidationError):
        Definition.model_validate(definition(steps=[{"id": "step", "action": action}]))


@pytest.mark.parametrize(
    "extra",
    [
        {"url": "http://169.254.169.254"},
        {"input": {"cmd": "whoami"}},
        {"expression": "x()"},
        {"params": {}},
        {"version": 2},
    ],
)
def test_untyped_parameters_cannot_enter_steps(extra: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Definition.model_validate(
            definition(steps=[{"id": "step", "action": "simulate_webhook", **extra}])
        )


@pytest.mark.parametrize("value", ["", " ", "a\x00b", "a\nb", "x" * 129, 12, "\ud800"])
def test_title_is_bounded_plain_text(value: Any) -> None:
    with pytest.raises(ValidationError):
        Definition.model_validate(definition(title=value))


@pytest.mark.parametrize(
    "steps",
    [
        [],
        [{"id": "same", "action": "notify_analyst"}] * 2,
        [{"id": f"step_{i}", "action": "notify_analyst"} for i in range(21)],
    ],
)
def test_steps_are_unique_and_bounded(steps: list[dict[str, Any]]) -> None:
    with pytest.raises(ValidationError):
        Definition.model_validate(definition(steps=steps))


@pytest.mark.parametrize("value", ["live", "real", "", None, True])
def test_only_simulation_is_admitted(value: Any) -> None:
    with pytest.raises(ValidationError):
        RunInput(revision=1, alert_id=uuid4(), execution_mode=value)


def test_catalog_and_permission_requirements_are_explicit() -> None:
    cap = catalog()
    assert not cap["automatic_triggers"] and not cap["network_actions"]
    assert len(cap["actions"]) == 9
    data = Definition.model_validate(
        definition(
            steps=[{"id": "case", "action": "create_incident"}, {"id": "ioc", "action": "add_ioc"}]
        )
    )
    assert {Permission.INCIDENTS_EDIT, Permission.INTELLIGENCE_MANAGE} <= required_permissions(data)
    assert Permission.INTELLIGENCE_MANAGE not in required_permissions(
        Definition.model_validate(definition())
    )


@pytest.mark.parametrize("version", [True, False, 1.0, "1", 2, None])
def test_schema_version_requires_exact_supported_integer(version: Any) -> None:
    with pytest.raises(ValidationError):
        Definition.model_validate(definition(schema_version=version))


def test_revision_proof_and_version_are_verified() -> None:
    data = Definition.model_validate(definition()).model_dump(mode="json")
    row = PlaybookRevision(
        document=data,
        canonical_document=canonical_json(data).decode(),
        document_sha256=digest(data),
        engine_version="local-soar-v1",
    )
    assert verified_revision(row).title == "Response"
    for field, wrong in (
        ("engine_version", "future"),
        ("canonical_document", "{}"),
        ("document_sha256", "0" * 64),
    ):
        old = getattr(row, field)
        setattr(row, field, wrong)
        with pytest.raises(ApiError):
            verified_revision(row)
        setattr(row, field, old)
    row.document = {**data, "unknown": "code"}
    with pytest.raises(ApiError):
        verified_revision(row)


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "169.254.169.254", "192.0.2.1", "::1", "2001:db8::1"]
)
@pytest.mark.parametrize(
    "action", ["enrich_ip", "simulate_block_ip", "simulate_isolate_host", "simulate_webhook"]
)
def test_infrastructure_actions_have_no_network_or_shell(
    address: str, action: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("SOAR attempted network or process execution")

    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("os.system", forbidden)
    context = {"ip": address, "host": "host.example", "risk": None}
    before = deepcopy(context)
    run = Mock(context=context, mode="live")
    result = execute_action(Mock(), run, Mock(action=action), Mock(), Mock())
    assert result["status"] == "completed"
    assert context == before
    if action.startswith("simulate_"):
        assert result["simulated"] is True and "SIMULATION" in result["reason"]


@pytest.mark.parametrize("action", ["enrich_ip", "simulate_block_ip", "add_ioc"])
def test_missing_ip_never_invents_target(action: str) -> None:
    result = execute_action(Mock(), Mock(context={"ip": None}), Mock(action=action), Mock(), Mock())
    assert result["status"] == "not_applicable"


def test_replay_ioc_never_changes_global_catalog() -> None:
    db = Mock()
    result = execute_action(
        db, Mock(context={"ip": "192.0.2.1"}, mode="replay"), Mock(action="add_ioc"), Mock(), Mock()
    )
    assert result["simulated"] is True
    assert not db.mock_calls


def test_unknown_risk_is_not_zero_or_artificially_increased() -> None:
    result = execute_action(
        Mock(),
        Mock(context={"ip": None, "risk": None}),
        Mock(action="calculate_risk"),
        Mock(),
        Mock(),
    )
    assert result["risk"] is None and result["status"] == "unavailable"


def test_unknown_action_fails_closed() -> None:
    with pytest.raises(ApiError):
        execute_action(
            Mock(), Mock(context={"ip": "127.0.0.1"}), Mock(action="shell"), Mock(), Mock()
        )
