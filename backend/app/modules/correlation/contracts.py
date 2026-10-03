"""Bounded native correlation definitions and operator-facing contracts."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.modules.mitre.schemas import MappingView
from app.modules.normalization.schemas import NormalizedSecurityEvent

EVALUATOR_VERSION = "correlation-v1"
ALLOWED_LATENESS_SECONDS = 120
MAX_CANDIDATES = 500
MAX_FUTURE_SECONDS = 30
GroupField = Literal["same_user", "same_host", "same_ip", "same_process"]


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    field: str | None = None
    operator: Literal["equals", "contains", "endswith"] | None = None
    value: str | None = None
    all: list["Condition"] | None = None
    any: list["Condition"] | None = None


class Stage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    count: int = Field(ge=1, le=20)
    condition: Condition


class Pattern(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["sequence", "threshold"]
    window_seconds: int = Field(ge=1, le=1800)
    group_by: list[GroupField] = Field(min_length=1, max_length=4)
    stages: list[Stage] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def bounded_proof(self) -> "Pattern":
        if sum(stage.count for stage in self.stages) > 100 or len(set(self.group_by)) != len(
            self.group_by
        ):
            raise ValueError("correlation proof exceeds supported limits")
        if (self.kind == "threshold" and len(self.stages) != 1) or (
            self.kind == "sequence" and len(self.stages) < 2
        ):
            raise ValueError("correlation kind and stage count disagree")
        return self


class CorrelationRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    version: str = "1.0.0"
    title: str
    description: str
    severity: Literal["medium", "high", "critical"]
    mitre: list[str]
    false_positive_guidance: list[str]
    references: list[str] = Field(default_factory=list)
    pattern: Pattern

    def snapshot(self) -> dict[str, Any]:
        return {
            **self.model_dump(mode="json"),
            "type": "correlation",
            "evaluator_version": EVALUATOR_VERSION,
            "allowed_lateness_seconds": ALLOWED_LATENESS_SECONDS,
            "max_candidates": MAX_CANDIDATES,
        }


class RuleView(BaseModel):
    mitre_mapping: MappingView
    id: str
    rule_version: str
    title: str
    description: str
    severity: str
    mitre: list[str]
    false_positive_guidance: list[str]
    references: list[str]
    pattern: Pattern
    type: Literal["correlation"] = "correlation"
    evaluator_version: str
    allowed_lateness_seconds: int
    max_candidates: int
    enabled: bool
    version: int
    updated_at: datetime
    updated_by: UUID | None


class RuleTest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=64)
    events: list[NormalizedSecurityEvent] = Field(min_length=1, max_length=100)


class ReplayFinalize(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dataset_id: UUID
    run_id: UUID
    expected_event_count: int = Field(strict=True, ge=1, le=10000)
