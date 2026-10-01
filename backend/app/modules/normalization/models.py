"""Immutable normalized evidence and independent durable projection progress."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database import Base, utcnow


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"
    __table_args__ = (CheckConstraint("jsonb_typeof(document) = 'object'", name="object_document"),)

    event_id: Mapped[UUID] = mapped_column(ForeignKey("raw_events.id"), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    schema_version: Mapped[str] = mapped_column(String(16))
    parser_version: Mapped[str] = mapped_column(String(32))
    document: Mapped[dict[str, Any]] = mapped_column(JSONB)
    document_sha256: Mapped[str] = mapped_column(String(64))


class PipelineJob(Base):
    __tablename__ = "pipeline_jobs"
    __table_args__ = (
        CheckConstraint(
            "state IN ('pending','normalizing','normalized','projecting','projected',"
            "'quarantined','projection_failed')",
            name="valid_state",
        ),
        CheckConstraint(
            "normalization_attempts >= 0 AND projection_attempts >= 0", name="nonnegative_attempts"
        ),
        CheckConstraint("version >= 1", name="positive_version"),
    )

    event_id: Mapped[UUID] = mapped_column(ForeignKey("raw_events.id"), primary_key=True)
    state: Mapped[str] = mapped_column(String(24), default="pending", server_default="pending")
    normalization_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    projection_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    lease_token: Mapped[UUID | None]
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")

    __mapper_args__ = {"version_id_col": version}
