"""Bounded profile filters and transparent projections of existing assessments."""

from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

EntityKind = Literal["host", "user", "ip", "process"]


class EntityFilters(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    mode: Literal["live", "replay"] = "live"
    dataset_id: UUID | None = None
    run_id: UUID | None = None
    from_: datetime | None = Field(default=None, alias="from")
    to: datetime | None = None
    kind: EntityKind | None = None
    q: str | None = Field(default=None, min_length=1, max_length=128)
    limit: int = Field(default=25, ge=1, le=100)
    cursor: str | None = Field(default=None, max_length=4096)

    @field_validator("from_", "to")
    @classmethod
    def utc(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            if value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError("UTC timezone is required")
            return value.astimezone(UTC)
        return value

    @field_validator("q")
    @classmethod
    def search(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or any(ord(c) < 32 for c in value)):
            raise ValueError("a nonempty text search is required")
        return value

    @model_validator(mode="after")
    def isolated(self) -> Self:
        if self.mode == "live":
            if self.dataset_id is not None or self.run_id not in (None, UUID(int=0)):
                raise ValueError("live includes all live sources")
        elif self.dataset_id in (None, UUID(int=0)) or self.run_id in (None, UUID(int=0)):
            raise ValueError("replay requires exact dataset and nonzero run")
        return self

    def window(self, now: datetime) -> tuple[datetime, datetime]:
        end = self.to or now
        start = self.from_ or end - timedelta(days=30)
        if start >= end or end > now or end - start > timedelta(days=366):
            raise ValueError("window must be past, positive and at most 366 days")
        return start, end


class EntityScope(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    mode: Literal["live", "replay"]
    dataset_id: UUID | None
    run_id: UUID | None
    from_: datetime = Field(alias="from")
    to: datetime
    time_basis: Literal["contributing_event.timestamp"] = "contributing_event.timestamp"
    interval: Literal["[from,to)"] = "[from,to)"


class EntityCounts(BaseModel):
    events: int
    observations: int
    failed_logins: int
    alerts: int
    eligible_alerts: int
    false_positive_alerts: int
    incidents: int


class EntitySummary(BaseModel):
    id: UUID
    kind: EntityKind
    label: str
    identity_policy: str
    identity_basis: str
    inventory_verified: Literal[False] = False
    source_id: UUID | None
    first_seen: datetime
    last_seen: datetime
    counts: EntityCounts
    risk_score: int | None
    risk_level: Literal["low", "medium", "high", "critical"] | None


class EntityRisk(BaseModel):
    strategy: Literal["maximum_current_eligible_alert"] = "maximum_current_eligible_alert"
    entity_calculation: Literal[False] = False
    score: int | None
    level: Literal["low", "medium", "high", "critical"] | None
    alert_id: UUID | None
    calculation_id: UUID | None
    policy_version: str | None
    explanation: dict[str, Any] | None
    eligible_alerts: int
    assessed_alerts: int
    excluded_false_positive_alerts: int
    reason: str


class EntityTechnique(BaseModel):
    id: str
    name: str
    url: str
    catalogue_version: str
    catalogue_hash: str
    alert_count: int


class EntityMitre(BaseModel):
    claim: Literal["candidate_association"] = "candidate_association"
    confirmed_attack: Literal[False] = False
    techniques: list[EntityTechnique]
    mapped_alerts: int
    unmapped_alerts: int
    legacy_alerts: int
    other_catalogue_alerts: int
    excluded_false_positive_alerts: int


class IndexStatus(BaseModel):
    pending_events: int
    pending_alerts: int
    complete: bool


class EntityDetail(EntitySummary):
    scope: EntityScope
    canonical_identity: dict[str, Any]
    risk: EntityRisk
    mitre: EntityMitre
    roles: dict[str, int]
    related_host_count: int
    index_status: IndexStatus


class EventActivity(BaseModel):
    event_id: UUID
    timestamp: datetime
    source_id: UUID
    source_name: str
    source_type: str
    event_category: str | None
    event_action: str | None
    event_outcome: str | None
    roles: list[str]


class EntityAlert(BaseModel):
    id: UUID
    title: str
    rule_id: str
    severity: str
    status: str
    event_timestamp: datetime
    contributing_event_count: int
    matched_entity_event_count: int
    risk_score: int | None
    risk_level: str | None


class EntityIncident(BaseModel):
    id: UUID
    title: str
    severity: str
    status: str
    created_at: datetime
    matched_alert_count: int
    risk_score: int | None
    risk_level: str | None


class EntityPage[Item](BaseModel):
    scope: EntityScope
    items: list[Item]
    total: int
    next_cursor: str | None
    index_status: IndexStatus


class BackfillInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit: int = Field(default=25, strict=True, ge=1, le=100)


class BackfillResult(BaseModel):
    events: int
    alerts: int
    observations: int
    index_status: IndexStatus
    identity_policy: str
