"""Bounded case contracts; scoring fields are read-only and initially uncomputed."""

from datetime import datetime
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.permissions import Role
from app.modules.alerts.schemas import AlertSummary, EventEvidence
from app.modules.mitre.schemas import IncidentMapping
from app.modules.normalization.schemas import NormalizedSecurityEvent
from app.modules.risk.schemas import RiskCalculationView, RiskLevel

IncidentStatus = Literal["new", "investigating", "contained", "resolved", "closed"]
IncidentSeverity = Literal["low", "medium", "high", "critical"]
Mode = Literal["live", "replay"]


def clean_text(value: str, *, multiline: bool = False, empty: bool = False) -> str:
    value = value.strip()
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("valid Unicode is required") from None
    if (not value and not empty) or any(
        (ord(char) < 32 and (not multiline or char not in "\n\r\t")) or ord(char) == 127
        for char in value
    ):
        raise ValueError("text cannot contain control characters")
    return value


class CaseInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @field_validator("title", "status_reason", check_fields=False)
    @classmethod
    def single_line(cls, value: str | None) -> str | None:
        return clean_text(value) if value is not None else value

    @field_validator("description", "body", check_fields=False)
    @classmethod
    def multiline(cls, value: str | None) -> str | None:
        return clean_text(value, multiline=True, empty=True) if value is not None else value

    @field_validator("tags", check_fields=False)
    @classmethod
    def clean_tags(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        cleaned = [clean_text(value).casefold() for value in values]
        if any(len(value) > 64 for value in cleaned) or len(set(cleaned)) != len(cleaned):
            raise ValueError("tags must be unique and at most 64 characters")
        return sorted(cleaned)


class IncidentCreate(CaseInput):
    title: str = Field(strict=True, min_length=1, max_length=256)
    description: str = Field(default="", strict=True, max_length=10000)
    severity: IncidentSeverity | None = None
    alert_ids: list[UUID] = Field(default_factory=list, max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=20)
    mode: Mode | None = None
    dataset_id: UUID | None = None
    run_id: UUID | None = None

    @field_validator("alert_ids")
    @classmethod
    def unique_alerts(cls, value: list[UUID]) -> list[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("alert identifiers must be distinct")
        return value


class IncidentPatch(CaseInput):
    title: str | None = Field(default=None, strict=True, min_length=1, max_length=256)
    description: str | None = Field(default=None, strict=True, max_length=10000)
    severity: IncidentSeverity | None = None
    status: IncidentStatus | None = None
    status_reason: str | None = Field(default=None, strict=True, min_length=1, max_length=1000)
    owner_id: UUID | None = None
    tags: list[str] | None = Field(default=None, max_length=20)

    @model_validator(mode="after")
    def changes(self) -> Self:
        if not self.model_fields_set or self.model_fields_set == {"status_reason"}:
            raise ValueError("at least one change is required")
        if any(getattr(self, key) is None for key in self.model_fields_set - {"owner_id"}):
            raise ValueError("only owner_id may be cleared")
        if self.status_reason is not None and self.status is None:
            raise ValueError("a status reason requires a status change")
        return self


class AlertAttach(CaseInput):
    alert_id: UUID


class NoteCreate(CaseInput):
    body: str = Field(strict=True, min_length=1, max_length=5000)

    @field_validator("body")
    @classmethod
    def nonempty(cls, value: str) -> str:
        if not value:
            raise ValueError("a nonempty note is required")
        return value


class PageFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit: int = Field(default=50, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=4096)


class IncidentFilters(PageFilters):
    status: IncidentStatus | None = None
    severity: IncidentSeverity | None = None
    owner_id: UUID | None = None
    tag: str | None = Field(default=None, strict=True, min_length=1, max_length=64)
    mode: Mode | None = None
    dataset_id: UUID | None = None
    run_id: UUID | None = None


class Actor(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    username: str
    role: Role


class IncidentSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    risk_score: int | None
    risk_level: RiskLevel | None = None
    risk_calculation_id: UUID | None = None
    confidence: int | None
    created_at: datetime
    updated_at: datetime
    first_seen: datetime | None
    last_seen: datetime | None
    owner_id: UUID | None
    owner: Actor | None = None
    tags: list[str]
    alert_count: int
    mode: Mode
    dataset_id: UUID | None
    run_id: UUID
    version: int


class TimelineView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    kind: str
    occurred_at: datetime
    actor: Actor | None
    data: dict[str, Any]


class NoteView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    body: str
    created_at: datetime
    author: Actor


class IncidentDetail(IncidentSummary):
    mitre_mapping: IncidentMapping | None = None
    risk_explanation: RiskCalculationView | None = None
    related_alerts: list[AlertSummary]
    related_users: list[str]
    related_hosts: list[str]
    related_ip_addresses: list[str]
    mitre_techniques: list[str]
    dataset_ids: list[UUID]
    evidence_count: int
    notes: list[NoteView]
    timeline: list[TimelineView]


class EvidenceView(BaseModel):
    id: UUID
    alert_id: UUID
    event_id: UUID
    source_id: UUID
    dataset_id: UUID
    mode: Mode
    run_id: UUID
    event_timestamp: datetime
    linked_at: datetime
    active: bool
    detached_at: datetime | None
    event_sha256: str
    rule_snapshot: dict[str, Any]
    event_snapshot: NormalizedSecurityEvent
    event_snapshots: list[EventEvidence]
    reason: dict[str, Any]


class Page[T](BaseModel):
    items: list[T]
    total: int
    next_cursor: str | None
