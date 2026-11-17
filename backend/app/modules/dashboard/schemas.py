"""Fixed time windows, explicit data provenance and bounded dashboard results."""

from datetime import UTC, datetime, timedelta
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class DashboardFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["live", "replay"] = "live"
    dataset_id: UUID | None = None
    run_id: UUID | None = None
    to: datetime | None = None
    include_false_positives: bool = False

    @field_validator("to")
    @classmethod
    def utc(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            if value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError("explicit UTC timestamp required")
            return value.astimezone(UTC)
        return value

    @model_validator(mode="after")
    def isolated(self) -> Self:
        if self.mode == "live":
            if self.dataset_id is not None or self.run_id not in (None, UUID(int=0)):
                raise ValueError("live covers live sources only")
        elif self.dataset_id in (None, UUID(int=0)) or self.run_id in (None, UUID(int=0)):
            raise ValueError("replay requires exact dataset and nonzero run")
        return self

    def window(self, now: datetime) -> tuple[datetime, datetime]:
        end = self.to or now
        if end > now or end.year < 1971:
            raise ValueError("past window required")
        return end - timedelta(hours=24), end


class Counts(BaseModel):
    events_24h: int = Field(ge=0)
    alerts_24h: int = Field(ge=0)
    excluded_false_positives: int = Field(ge=0)
    open_incidents: int = Field(ge=0)
    critical_incidents: int = Field(ge=0)
    received_24h: int = Field(ge=0)


class CategoryCount(BaseModel):
    id: str
    label: str
    count: int = Field(ge=0)


class EntityRank(BaseModel):
    id: UUID
    label: str
    identity_basis: str
    count: int = Field(ge=1)


class RuleRank(BaseModel):
    id: str
    version: str
    label: str
    count: int = Field(ge=1)


class TopEntities(BaseModel):
    users: list[EntityRank] = Field(max_length=10)
    hosts: list[EntityRank] = Field(max_length=10)
    source_ips: list[EntityRank] = Field(max_length=10)
    destination_ips: list[EntityRank] = Field(max_length=10)


class IndexStatus(BaseModel):
    pending_events: int = Field(ge=0)
    indexed_events: int = Field(ge=0)
    entities_partial: bool


class IngestionBucket(BaseModel):
    from_: datetime = Field(alias="from")
    to: datetime
    count: int = Field(ge=0)
    events_per_second: float = Field(ge=0)


class IngestionRate(BaseModel):
    time_basis: Literal["raw_events.received_at"] = "raw_events.received_at"
    bucket_seconds: Literal[60] = 60
    accepted_events: int = Field(ge=0)
    average_eps: float = Field(ge=0)
    buckets: list[IngestionBucket] = Field(min_length=60, max_length=60)


class DashboardScope(BaseModel):
    mode: Literal["live", "replay"]
    dataset_id: UUID | None
    run_id: UUID | None
    from_: datetime = Field(alias="from")
    to: datetime
    include_false_positives: bool
    event_time_basis: Literal["normalized_events.timestamp"] = "normalized_events.timestamp"
    alert_time_basis: Literal["alerts.event_timestamp"] = "alerts.event_timestamp"
    incident_basis: Literal["current_open_cases_all_time"] = "current_open_cases_all_time"
    interval: Literal["[from,to)"] = "[from,to)"


class MitreStatus(BaseModel):
    mapped_alerts: int = Field(ge=0)
    unmapped_alerts: int = Field(ge=0)
    missing_snapshots: int = Field(ge=0)
    other_catalogue_alerts: int = Field(ge=0)


class DashboardReport(BaseModel):
    generated_at: datetime
    scope: DashboardScope
    refresh_seconds: Literal[10] = 10
    counts: Counts
    index_status: IndexStatus
    top: TopEntities
    rules: list[RuleRank] = Field(max_length=10)
    severity: list[CategoryCount]
    risk: list[CategoryCount]
    tactics: list[CategoryCount]
    mitre_status: MitreStatus
    ingestion: IngestionRate
