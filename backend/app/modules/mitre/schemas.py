"""Explicit candidate associations; catalogue labels do not establish attacker intent."""

from datetime import UTC, datetime, timedelta
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Reference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str
    url: str


class TechniqueMapping(Reference):
    tactics: list[Reference]


class MappingView(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["mapped", "unmapped", "legacy_unmapped"]
    claim: Literal["candidate_association"] = "candidate_association"
    confirmed_attack: Literal[False] = False
    catalogue_version: str | None
    catalogue_hash: str | None
    mapping_version: str | None
    mapping_hash: str | None
    techniques: list[TechniqueMapping] = Field(max_length=20)
    reason: str


class IncidentTechnique(TechniqueMapping):
    catalogue_version: str
    catalogue_hash: str


class IncidentMapping(BaseModel):
    claim: Literal["candidate_association"] = "candidate_association"
    confirmed_attack: Literal[False] = False
    techniques: list[IncidentTechnique]
    mapped_alerts: int
    unmapped_alerts: int
    legacy_alerts: int
    excluded_false_positive_alerts: int


class CatalogueMeta(BaseModel):
    domain: Literal["enterprise-attack"] = "enterprise-attack"
    version: str
    sha256: str
    source_url: str
    source_sha256: str
    source_commit: str
    attribution: str
    license_url: str
    tactics_count: int
    techniques_count: int


class TacticView(Reference):
    short_name: str


class TechniqueView(Reference):
    parent_id: str | None
    tactic_ids: list[str]
    is_subtechnique: bool


class CatalogueView(BaseModel):
    catalogue: CatalogueMeta
    tactics: list[TacticView]
    techniques: list[TechniqueView]


class CoverageFilters(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    mode: Literal["live", "replay"] = "live"
    from_: datetime | None = Field(default=None, alias="from")
    to: datetime | None = None
    dataset_id: UUID | None = None
    run_id: UUID | None = None
    include_false_positives: bool = False

    @field_validator("from_", "to")
    @classmethod
    def aware_utc(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            if value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError("UTC timestamp with timezone is required")
            value = value.astimezone(UTC)
        return value

    @model_validator(mode="after")
    def isolated_scope(self) -> Self:
        if self.mode == "live":
            if self.dataset_id is not None or self.run_id not in (None, UUID(int=0)):
                raise ValueError("live coverage covers all sources in the live run")
        elif self.dataset_id is None or self.run_id in (None, UUID(int=0)):
            raise ValueError("replay coverage requires exact dataset and nonzero run")
        return self

    def window(self, now: datetime) -> tuple[datetime, datetime]:
        end = self.to or now
        start = self.from_ or end - timedelta(days=30)
        if start >= end or end > now or end - start > timedelta(days=366):
            raise ValueError("coverage window must be positive, past and at most 366 days")
        return start, end


class CoverageScope(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    mode: Literal["live", "replay"]
    from_: datetime = Field(alias="from")
    to: datetime
    dataset_id: UUID | None
    run_id: UUID | None
    include_false_positives: bool
    time_basis: Literal["alert.event_timestamp"] = "alert.event_timestamp"
    interval: Literal["[from,to)"] = "[from,to)"


class CoverageCounts(BaseModel):
    configured_rule_count: int
    enabled_rule_count: int
    alert_count: int
    incident_count: int


class TacticCoverage(TacticView, CoverageCounts):
    pass


class TechniqueCoverage(TechniqueView, CoverageCounts):
    pass


class CoverageSummary(BaseModel):
    eligible_alerts: int
    mapped_alerts: int
    unmapped_alerts: int
    legacy_alerts: int
    other_catalogue_alerts: int
    excluded_false_positive_alerts: int
    incidents: int
    observed_techniques: int
    observed_tactics: int
    configured_techniques: int
    enabled_techniques: int
    configured_tactics: int
    enabled_tactics: int


class CoverageView(BaseModel):
    catalogue: CatalogueMeta
    scope: CoverageScope
    claim: Literal["candidate_association"] = "candidate_association"
    confirmed_attack: Literal[False] = False
    tactics: list[TacticCoverage]
    techniques: list[TechniqueCoverage]
    summary: CoverageSummary
