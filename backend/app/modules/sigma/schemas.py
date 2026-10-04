"""Reviewable import and optimistic deployment contracts."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.modules.mitre.schemas import MappingView
from app.modules.normalization.schemas import NormalizedSecurityEvent


class YamlInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    yaml: str = Field(min_length=1, max_length=65536)


class TestInput(YamlInput):
    events: list[NormalizedSecurityEvent] = Field(min_length=1, max_length=25)


class DeploymentPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = Field(strict=True)


class DefinitionView(BaseModel):
    sigma_id: UUID
    title: str
    description: str
    severity: str
    mitre: list[str]
    false_positive_guidance: list[str]
    references: list[str]
    evaluator_version: str
    source_types: list[str]
    source_sha256: str
    compiled_sha256: str
    mitre_mapping: MappingView


class VersionView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    revision: int
    id: UUID
    source_sha256: str
    compiled_sha256: str
    created_at: datetime
    created_by: UUID


class RuleView(DefinitionView):
    id: UUID
    revision: int
    revision_id: UUID
    enabled: bool
    version: int
    updated_at: datetime
    updated_by: UUID | None


class RuleDetail(RuleView):
    definition_yaml: str
    compiled: dict[str, Any]
    versions: list[VersionView]
