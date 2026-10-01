"""Explicit bounded search input and nested normalized output."""

from datetime import UTC, datetime, timedelta
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from app.modules.events.query import parse_query
from app.modules.ingestion.schemas import RFC3339_TIMESTAMP
from app.modules.normalization.schemas import NormalizedSecurityEvent


class SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    from_: AwareDatetime | None = Field(default=None, alias="from")
    to: AwareDatetime | None = None
    q: str = Field(default="", max_length=4096)
    mode: Literal["live", "replay"] | None = None
    dataset_id: UUID | None = None
    source_id: UUID | None = None
    run_id: UUID | None = None
    limit: int = Field(default=100, ge=1, le=500, strict=True)
    cursor: str | None = Field(default=None, min_length=1, max_length=4096)

    @field_validator("from_", "to", mode="before")
    @classmethod
    def explicit_timestamp(cls, value: object) -> object:
        if value is not None and not isinstance(value, datetime):
            if not isinstance(value, str) or not RFC3339_TIMESTAMP.fullmatch(value):
                raise ValueError("an RFC3339 timestamp with explicit offset is required")
        return value

    @field_validator("from_", "to")
    @classmethod
    def normalize_time(cls, value: datetime | None) -> datetime | None:
        return value.astimezone(UTC) if value is not None else None

    @field_validator("q")
    @classmethod
    def validate_query(cls, value: str) -> str:
        parse_query(value)
        return value

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        if self.from_ is not None and self.to is not None:
            check_window(self.from_, self.to)
        return self


def check_window(start: datetime, end: datetime) -> None:
    if start.year < 1970 or start.year > 2299 or end.year < 1970 or end.year > 2299:
        raise ValueError("search timestamps must be in the supported 1970–2299 UTC range")
    if start >= end or end - start > timedelta(days=7):
        raise ValueError("search window must be positive and no greater than seven days")


class SearchResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    items: list[NormalizedSecurityEvent]
    total: int
    next_cursor: str | None
    from_: datetime = Field(alias="from")
    to: datetime


class SearchParams(SearchRequest):
    # URL parameters are strings; JSON request limits remain strictly numeric.
    limit: int = Field(default=100, ge=1, le=500)
