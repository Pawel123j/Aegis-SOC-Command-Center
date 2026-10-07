"""Explicit daily windows and transparent statistical output."""

from datetime import UTC, date, datetime, timedelta
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class UebaFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["live", "replay"] = "live"
    dataset_id: UUID | None = None
    run_id: UUID | None = None
    day: date | None = None

    @model_validator(mode="after")
    def isolated(self) -> Self:
        if self.mode == "live":
            if self.dataset_id is not None or self.run_id not in (None, UUID(int=0)):
                raise ValueError("live includes all live sources")
        elif self.dataset_id in (None, UUID(int=0)) or self.run_id in (None, UUID(int=0)):
            raise ValueError("replay requires exact dataset and nonzero run")
        return self

    def window(self, now: datetime) -> tuple[datetime, datetime, datetime]:
        today = now.astimezone(UTC).date()
        selected = self.day or today - timedelta(days=1)
        if selected >= today or selected < date(1970, 1, 29):
            raise ValueError("a complete past UTC day within the storage range is required")
        start = datetime.combine(selected, datetime.min.time(), tzinfo=UTC)
        return start - timedelta(days=28), start, start + timedelta(days=1)


class UebaEvidenceFilters(UebaFilters):
    document_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class UebaEntity(BaseModel):
    id: UUID
    kind: Literal["host", "user", "ip", "process"]
    label: str
    identity_basis: str


class UebaScope(BaseModel):
    mode: Literal["live", "replay"]
    dataset_id: UUID | None
    run_id: UUID | None


class Observation(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    from_: datetime = Field(alias="from")
    to: datetime
    event_count: int
    eligible_events: int
    excluded_timestamp_events: int


class Baseline(Observation):
    days: Literal[28] = 28
    active_days: int
    minimum_events: Literal[20] = 20
    minimum_active_days: Literal[7] = 7


class Evidence(BaseModel):
    event_id: UUID
    timestamp: datetime
    document_sha256: str


class Indicator(BaseModel):
    id: Literal[
        "unusual_login_hour",
        "new_login_ip",
        "new_login_host",
        "first_admin_tool",
        "failed_login_burst",
        "activity_burst",
        "admin_account_use",
    ]
    status: Literal["anomaly", "normal", "insufficient_data", "unsupported"]
    score: int = Field(ge=0, le=100)
    explanation: str
    baseline_event_count: int = 0
    baseline_active_days: int = 0
    baseline_values: list[str] = Field(default_factory=list)
    observed_count: int = 0
    observed_values: list[str] = Field(default_factory=list)
    daily_mean: float | None = None
    daily_stddev: float | None = None
    threshold: int | None = None
    evidence_total: int = 0
    evidence: list[Evidence] = Field(default_factory=list)


class UebaReport(BaseModel):
    policy_version: Literal["ueba-statistics-v1"] = "ueba-statistics-v1"
    as_of: datetime
    entity: UebaEntity
    scope: UebaScope
    observation: Observation
    baseline: Baseline
    status: Literal["ready", "cold_start", "index_pending", "unsupported"]
    pending_events: int
    score: int | None = Field(ge=0, le=100)
    indicators: list[Indicator]
