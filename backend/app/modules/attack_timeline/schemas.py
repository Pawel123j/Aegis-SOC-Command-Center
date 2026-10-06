"""Bounded observed-event projection, without inferred attack stages."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.modules.normalization.schemas import NormalizedSecurityEvent


class TimelineQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    limit: int = Field(default=25, ge=1, le=25)
    cursor: str | None = Field(default=None, min_length=1, max_length=4096)


class AlertReference(BaseModel):
    id: UUID
    title: str
    severity: Literal["informational", "low", "medium", "high", "critical"]
    status: Literal["new", "acknowledged", "false_positive", "resolved"]
    detection_type: Literal["single_event", "correlation", "sigma", "intelligence"]
    rule_id: str
    rule_version: str
    linked_at: datetime


class TimelineEvent(BaseModel):
    event_id: UUID
    event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_snapshot: NormalizedSecurityEvent
    alerts: list[AlertReference] = Field(min_length=1, max_length=100)


class IndexStatus(BaseModel):
    eligible_alerts: int = Field(ge=0, le=100)
    indexed_alerts: int = Field(ge=0, le=100)
    pending_alerts: int = Field(ge=0, le=100)
    complete: bool


class AttackTimeline(BaseModel):
    incident_id: UUID
    incident_version: int = Field(ge=1)
    mode: Literal["live", "replay"]
    dataset_id: UUID | None
    run_id: UUID
    projection_version: Literal["attack-timeline-v1"] = "attack-timeline-v1"
    view_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    total: int = Field(ge=0, le=10000)
    index_status: IndexStatus
    items: list[TimelineEvent] = Field(max_length=25)
    next_cursor: str | None
