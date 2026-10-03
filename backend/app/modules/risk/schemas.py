"""Bounded scoring inputs and immutable assessment views."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

RiskLevel = Literal["low", "medium", "high", "critical"]
Family = Literal[
    "authentication_attack", "suspicious_execution", "privilege_change", "account_change"
]
ContextKind = Literal[
    "host_criticality",
    "user_importance",
    "ioc_reputation",
    "attack_tactics",
    "confirmed_history",
    "prior_privileges",
]


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Provenance(StrictInput):
    source: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    as_of: datetime

    @model_validator(mode="after")
    def aware(self) -> "Provenance":
        if self.as_of.tzinfo is None:
            raise ValueError("context date must have a timezone")
        return self


class EvidenceReference(StrictInput):
    id: UUID
    timestamp: datetime
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def aware(self) -> "EvidenceReference":
        if self.timestamp.tzinfo is None:
            raise ValueError("event date must have a timezone")
        return self


class Signal(StrictInput):
    id: str = Field(min_length=1, max_length=128)
    family: Family
    severity: Literal["informational", "low", "medium", "high", "critical"]
    evidence_ids: list[UUID] = Field(min_length=1, max_length=100)
    alert_ids: list[UUID] = Field(default_factory=list, max_length=100)
    confidence: int | None = Field(default=None, strict=True, ge=0, le=100)
    confidence_provenance: Provenance | None = None

    @model_validator(mode="after")
    def confidence_source(self) -> "Signal":
        if (self.confidence is None) != (self.confidence_provenance is None):
            raise ValueError("confidence requires versioned provenance")
        return self


class ContextFact(StrictInput):
    kind: ContextKind
    value: str = Field(min_length=1, max_length=128)
    evidence_ids: list[UUID] = Field(min_length=1, max_length=100)
    provenance: Provenance
    subject_key: str | None = Field(default=None, min_length=1, max_length=512)
    confidence: int | None = Field(default=None, strict=True, ge=0, le=100)
    active: bool = True
    expires_at: datetime | None = None
    observed_at: datetime | None = None
    prior_incident_id: UUID | None = None
    prior_evidence_ids: list[UUID] = Field(default_factory=list, max_length=100)
    prior_mode: Literal["live", "replay"] | None = None
    prior_dataset_id: UUID | None = None
    prior_run_id: UUID | None = None

    @model_validator(mode="after")
    def values(self) -> "ContextFact":
        options = {
            "host_criticality": {"low", "medium", "high", "critical"},
            "user_importance": {"low", "medium", "high", "critical"},
            "ioc_reputation": {"unknown", "suspicious", "malicious"},
            "prior_privileges": {"standard", "privileged", "administrator"},
            "confirmed_history": {"confirmed_malicious"},
        }
        if self.kind in options and self.value not in options[self.kind]:
            raise ValueError("unknown context value")
        if any(
            value is not None and value.tzinfo is None
            for value in (self.observed_at, self.expires_at)
        ):
            raise ValueError("observation date must have a timezone")
        if self.kind == "confirmed_history" and (
            self.observed_at is None
            or self.prior_incident_id is None
            or self.subject_key is None
            or self.prior_mode is None
            or self.prior_run_id is None
            or not self.prior_evidence_ids
        ):
            raise ValueError("confirmed history requires identity, verdict and scope provenance")
        if self.kind == "prior_privileges" and (
            self.observed_at is None or self.subject_key is None
        ):
            raise ValueError("prior privileges require dated strong identity")
        if self.kind in {"host_criticality", "user_importance"} and self.subject_key is None:
            raise ValueError("asset and account facts require a strong subject identity")
        if self.kind == "attack_tactics" and (
            len(self.value) != 6 or not self.value.startswith("TA") or not self.value[2:].isdigit()
        ):
            raise ValueError("verified tactic IDs must use TA followed by four digits")
        return self


class RiskInput(StrictInput):
    evidence: list[EvidenceReference] = Field(default_factory=list, max_length=10000)
    signals: list[Signal] = Field(default_factory=list, max_length=500)
    contexts: list[ContextFact] = Field(default_factory=list, max_length=100)
    known_contexts: list[ContextKind] = Field(default_factory=list, max_length=6)
    subject_keys: list[str] = Field(default_factory=list, max_length=1000)
    subject_id: UUID | None = None
    excluded_incident_ids: list[UUID] = Field(default_factory=list, max_length=100)
    mode: Literal["live", "replay"] = "live"
    dataset_id: UUID | None = None
    run_id: UUID = UUID(int=0)

    @model_validator(mode="after")
    def integrity(self) -> "RiskInput":
        events = {item.id: item for item in self.evidence}
        if len(events) != len(self.evidence):
            raise ValueError("evidence references must be unique")
        facts: list[Signal | ContextFact] = [*self.signals, *self.contexts]
        for item in facts:
            if not set(item.evidence_ids) <= events.keys():
                raise ValueError("all facts must cite supplied evidence")
        if self.mode == "replay" and (self.dataset_id is None or self.run_id.int == 0):
            raise ValueError("replay requires dataset and nonzero run")
        if self.mode == "live" and (self.dataset_id is not None or self.run_id.int != 0):
            raise ValueError("live scope cannot contain replay metadata")
        return self


class RiskComponent(BaseModel):
    code: str
    label: str
    points: int
    maximum: int
    status: Literal["known", "unknown", "not_applicable"]
    reason: str
    evidence_ids: list[UUID]
    details: dict[str, Any]


class SignalUnit(BaseModel):
    family: Family
    evidence_ids: list[UUID]
    alert_ids: list[UUID]


class RiskResult(BaseModel):
    score: int
    level: RiskLevel
    raw_score: int
    clipping: int
    components: list[RiskComponent]
    signal_units: list[SignalUnit]
    missing_contexts: list[str]
    confidence_status: Literal["known", "unknown", "mixed", "not_applicable"]


class RiskCalculationView(RiskResult):
    id: UUID
    subject_type: Literal["alert", "incident"]
    subject_id: UUID
    subject_revision: int
    created_at: datetime
    actor_id: UUID | None
    trigger: str
    previous_id: UUID | None
    policy_version: str
    policy_hash: str
    input_sha256: str
    input_snapshot: dict[str, Any]
    excluded_alert_ids: list[UUID]


class RiskHistory(BaseModel):
    current: RiskCalculationView | None
    history: list[RiskCalculationView]
    history_truncated: bool


class BackfillInput(StrictInput):
    limit: int = Field(default=25, strict=True, ge=1, le=100)
