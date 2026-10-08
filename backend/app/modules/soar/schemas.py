"""Small typed definitions: no expressions, URLs, code or arbitrary action arguments."""

import hashlib
from types import MappingProxyType
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.permissions import Permission
from app.modules.ingestion.schemas import canonical_json

ENGINE_VERSION = "local-soar-v1"
MAX_PLAYBOOKS = 100
MAX_REVISIONS = 20
MAX_ACTIVE_RUNS = 100
MAX_OUTPUT_BYTES = 65536
Action = Literal[
    "enrich_ip",
    "check_threat_intelligence",
    "calculate_risk",
    "create_incident",
    "add_ioc",
    "notify_analyst",
    "simulate_block_ip",
    "simulate_isolate_host",
    "simulate_webhook",
]
ACTION_LABELS = MappingProxyType(
    {
        "enrich_ip": "Sprawdź adres IP lokalnie",
        "check_threat_intelligence": "Odczytaj zachowany dowód Threat Intelligence",
        "calculate_risk": "Pokaż wyjaśnioną ocenę ryzyka",
        "create_incident": "Utwórz lub powiąż otwarty incydent",
        "add_ioc": "Dodaj nieaktywny IOC do przeglądu (replay: symulacja)",
        "notify_analyst": "Dodaj powiadomienie w aplikacji",
        "simulate_block_ip": "Symuluj blokadę adresu IP",
        "simulate_isolate_host": "Symuluj izolację komputera",
        "simulate_webhook": "Symuluj wywołanie webhooka",
    }
)
BASE_PERMISSIONS = frozenset(
    {
        Permission.PLAYBOOKS_RUN,
        Permission.PLAYBOOKS_READ,
        Permission.ALERTS_READ,
        Permission.EVENTS_READ,
        Permission.INCIDENTS_READ,
        Permission.INTELLIGENCE_READ,
    }
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class Step(StrictModel):
    id: str = Field(min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_]*$", strict=True)
    action: Action


class Definition(StrictModel):
    schema_version: Literal[1] = 1
    title: str = Field(min_length=1, max_length=128, strict=True)
    description: str = Field(default="", max_length=1024, strict=True)
    steps: list[Step] = Field(min_length=1, max_length=20)

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_version(cls, value: Any) -> Any:
        if type(value) is not int or value != 1:
            raise ValueError("supported integer schema version required")
        return value

    @field_validator("title", "description")
    @classmethod
    def safe_text(cls, value: str) -> str:
        if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise ValueError("plain text required")
        return value.strip()

    @model_validator(mode="after")
    def unique_steps(self) -> Self:
        if not self.title or len({step.id for step in self.steps}) != len(self.steps):
            raise ValueError("nonempty title and unique step IDs required")
        return self


class RunInput(StrictModel):
    revision: int = Field(strict=True, ge=1, le=MAX_REVISIONS)
    alert_id: UUID
    event_id: UUID | None = None
    ip_field: Literal["source", "destination"] = "source"
    execution_mode: Literal["simulation"] = "simulation"
    replay_of: UUID | None = None


class Publication(StrictModel):
    revision: int = Field(strict=True, ge=1, le=MAX_REVISIONS)


class Availability(StrictModel):
    enabled: bool = Field(strict=True)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def required_permissions(definition: Definition) -> frozenset[Permission]:
    result = set(BASE_PERMISSIONS)
    for step in definition.steps:
        if step.action == "create_incident":
            result.add(Permission.INCIDENTS_EDIT)
        if step.action == "add_ioc":
            result.add(Permission.INTELLIGENCE_MANAGE)
    return frozenset(result)


def catalog() -> dict[str, Any]:
    return {
        "engine_version": ENGINE_VERSION,
        "execution_mode": "simulation",
        "actions": [
            {
                "id": key,
                "label": value,
                "infrastructure_simulated": key.startswith("simulate_"),
                "required_permission": (
                    "intelligence:manage"
                    if key == "add_ioc"
                    else "incidents:edit"
                    if key == "create_incident"
                    else "playbooks:run"
                ),
            }
            for key, value in ACTION_LABELS.items()
        ],
        "max_steps": 20,
        "max_revisions": MAX_REVISIONS,
        "max_playbooks": MAX_PLAYBOOKS,
        "max_attempts": 3,
        "lease_seconds": 30,
        "deadline_seconds": 600,
        "automatic_triggers": False,
        "network_actions": False,
    }
