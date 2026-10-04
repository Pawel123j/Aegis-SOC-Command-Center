"""Initial per-event alert contracts; risk remains explicitly uncomputed."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.modules.mitre.schemas import MappingView
from app.modules.normalization.schemas import NormalizedSecurityEvent
from app.modules.risk.schemas import RiskCalculationView, RiskLevel

AlertStatus = Literal["new", "acknowledged", "false_positive", "resolved"]
Severity = Literal["informational", "low", "medium", "high", "critical"]


class AlertFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit: int = Field(default=100, ge=1, le=500)
    status: AlertStatus | None = None
    severity: Severity | None = None
    mode: Literal["live", "replay"] | None = None
    dataset_id: UUID | None = None
    source_id: UUID | None = None
    run_id: UUID | None = None
    cursor: str | None = Field(default=None, min_length=1, max_length=4096)


class AlertSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    title: str
    severity: Severity
    status: AlertStatus
    event_id: UUID
    source_id: UUID
    dataset_id: UUID
    run_id: UUID
    mode: Literal["live", "replay"]
    rule_id: str
    rule_version: str
    evaluator_version: str
    event_timestamp: datetime
    created_at: datetime
    updated_at: datetime
    version: int
    risk_score: int | None
    risk_level: RiskLevel | None = None
    risk_calculation_id: UUID | None = None
    event_count: int = 1
    detection_type: Literal["single_event", "correlation", "sigma"] = "single_event"


class EventEvidence(BaseModel):
    event_id: UUID
    event_sha256: str
    event_snapshot: NormalizedSecurityEvent


class AlertDetail(AlertSummary):
    mitre_mapping: MappingView | None = None
    risk_explanation: RiskCalculationView | None = None
    acknowledged_at: datetime | None
    acknowledged_by: UUID | None
    updated_by: UUID | None
    rule_snapshot: dict[str, Any]
    event_snapshot: NormalizedSecurityEvent
    reason: dict[str, Any]
    event_sha256: str
    event_snapshots: list[EventEvidence] = Field(default_factory=list)

    @model_validator(mode="after")
    def legacy_evidence(self) -> "AlertDetail":
        if not self.event_snapshots:
            self.event_snapshots = [
                EventEvidence(
                    event_id=self.event_id,
                    event_sha256=self.event_sha256,
                    event_snapshot=self.event_snapshot,
                )
            ]
        return self


class AlertList(BaseModel):
    items: list[AlertSummary]
    total: int
    next_cursor: str | None


class AlertPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: AlertStatus
