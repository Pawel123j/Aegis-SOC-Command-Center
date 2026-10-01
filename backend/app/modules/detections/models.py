"""Fixed rule deployment configuration and durable per-event evaluation checkpoints."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database import Base, utcnow


class RuleDeployment(Base):
    __tablename__ = "rule_deployments"
    __table_args__ = (CheckConstraint("version >= 1", name="positive_version"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule_version: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")

    __mapper_args__ = {"version_id_col": version}


class DetectionJob(Base):
    __tablename__ = "detection_jobs"
    __table_args__ = (
        CheckConstraint("state IN ('pending','processed','quarantined')", name="valid_state"),
        CheckConstraint("jsonb_typeof(evaluated_rules) = 'array'", name="array_rules"),
    )

    event_id: Mapped[UUID] = mapped_column(
        ForeignKey("normalized_events.event_id"), primary_key=True
    )
    state: Mapped[str] = mapped_column(
        String(24), default="pending", server_default="pending", index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))
    evaluated_rules: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
