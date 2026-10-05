"""Bounded local catalog inputs and exact, immutable revision documents."""

from datetime import UTC, datetime
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator, model_validator

IndicatorType = Literal["ip", "domain", "url", "hash"]
Reputation = Literal["unknown", "clean", "suspicious", "malicious"]


class Metadata(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    reputation: Reputation = "unknown"
    confidence: int | None = Field(default=None, strict=True, ge=0, le=100)
    source: str = Field(min_length=1, max_length=128, strict=True)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list[StrictStr] = Field(default_factory=list, max_length=16)
    description: str = Field(default="", max_length=2048, strict=True)
    active: bool = Field(default=True, strict=True)

    @field_validator("source")
    @classmethod
    def source_text(cls, value: str) -> str:
        if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise ValueError("source must be nonempty text")
        value = value.strip()
        if not value or any(
            ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value
        ):
            raise ValueError("source must be nonempty text")
        return value

    @field_validator("description")
    @classmethod
    def description_text(cls, value: str) -> str:
        if any(
            (ord(c) < 32 and c not in "\n\r\t") or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF
            for c in value
        ):
            raise ValueError("NUL is unsupported")
        return value

    @field_validator("tags")
    @classmethod
    def tag_text(cls, values: list[str]) -> list[str]:
        if any(
            any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
            for value in values
        ):
            raise ValueError("tags must be distinct bounded text")
        result = [value.strip() for value in values]
        if any(
            not value
            or len(value) > 64
            or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
            for value in result
        ) or len(set(result)) != len(result):
            raise ValueError("tags must be distinct bounded text")
        return result

    @field_validator("first_seen", "last_seen")
    @classmethod
    def seen_time(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            if value.tzinfo is None or not 1970 <= value.year < 2300:
                raise ValueError("bounded aware timestamp required")
            value = value.astimezone(UTC)
            if not 1970 <= value.year < 2300:
                raise ValueError("bounded aware timestamp required")
            return value
        return value

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if (
            self.first_seen is not None
            and self.last_seen is not None
            and self.first_seen > self.last_seen
        ):
            raise ValueError("first_seen must precede last_seen")
        return self


class IOCInput(Metadata):
    type: IndicatorType
    value: str = Field(min_length=1, max_length=2048, strict=True)


class IOCPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    reputation: Reputation | None = None
    confidence: int | None = Field(default=None, strict=True, ge=0, le=100)
    source: str | None = Field(default=None, min_length=1, max_length=128, strict=True)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list[StrictStr] | None = Field(default=None, max_length=16)
    description: str | None = Field(default=None, max_length=2048, strict=True)
    active: bool | None = Field(default=None, strict=True)

    @model_validator(mode="after")
    def nonempty(self) -> Self:
        if not self.model_fields_set or any(
            getattr(self, key) is None
            for key in self.model_fields_set
            & {"reputation", "source", "tags", "description", "active"}
        ):
            raise ValueError("a nonempty metadata patch is required")
        return self


class RevisionDocument(IOCInput):
    ioc_id: UUID
    revision_id: UUID
    revision: int = Field(ge=1, le=50)
    canonical_value: str = Field(min_length=1, max_length=2048)
    normalization_version: Literal["ioc-normalization-v1"] = "ioc-normalization-v1"


class IOCView(IOCInput):
    id: UUID
    canonical_value: str
    normalization_version: str
    revision: int
    revision_id: UUID
    document_sha256: str
    version: int
    created_at: datetime
    created_by: UUID
    updated_at: datetime
    updated_by: UUID


class IOCFilters(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    kind: IndicatorType | None = None
    reputation: Reputation | None = None
    active: bool | None = None
    q: str | None = Field(default=None, min_length=1, max_length=128)
    limit: int = Field(default=25, ge=1, le=100)
    cursor: str | None = Field(default=None, max_length=4096)

    @field_validator("q")
    @classmethod
    def literal(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or any(ord(c) < 32 for c in value)):
            raise ValueError("nonempty literal text required")
        return value


class IOCLimits(BaseModel):
    max_iocs: Literal[1000] = 1000
    max_revisions: Literal[50] = 50
    max_import: Literal[100] = 100


class IOCPage(BaseModel):
    items: list[IOCView]
    total: int
    next_cursor: str | None
    normalization_version: str
    limits: IOCLimits = Field(default_factory=IOCLimits)


class RevisionView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    ioc_id: UUID
    revision: int
    document: dict[str, Any]
    document_sha256: str
    created_at: datetime
    created_by: UUID


class IOCHistory(BaseModel):
    items: list[RevisionView]
    total: int
    next_cursor: str | None


class IOCImport(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    items: list[IOCInput] = Field(min_length=1, max_length=100)


class ImportResult(BaseModel):
    items: list[IOCView]
    created: int
    unchanged: int


class LookupInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    type: IndicatorType
    value: str = Field(min_length=1, max_length=2048, strict=True)


class LookupResult(BaseModel):
    type: IndicatorType
    canonical_value: str
    normalization_version: str
    found: bool
    item: IOCView | None
