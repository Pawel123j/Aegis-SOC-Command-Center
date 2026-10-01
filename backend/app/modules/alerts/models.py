"""Immutable evidence, with only analyst disposition columns writable at runtime."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database import Base, utcnow


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint(
            "status IN ('new','acknowledged','false_positive','resolved')", name="valid_status"
        ),
        CheckConstraint(
            "severity IN ('informational','low','medium','high','critical')", name="valid_severity"
        ),
        CheckConstraint("mode IN ('live','replay')", name="valid_mode"),
        CheckConstraint("version >= 1", name="positive_version"),
        CheckConstraint("risk_score IS NULL OR risk_score BETWEEN 0 AND 100", name="bounded_risk"),
        CheckConstraint(
            "jsonb_typeof(rule_snapshot) = 'object' AND "
            "jsonb_typeof(event_snapshot) = 'object' AND jsonb_typeof(reason) = 'object'",
            name="object_evidence",
        ),
        CheckConstraint(
            "jsonb_typeof(event_snapshots) = 'array' AND "
            "jsonb_array_length(event_snapshots) <= 100",
            name="array_event_snapshots",
        ),
        Index("ix_alerts_created_at_id", "created_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    detection_key: Mapped[str] = mapped_column(String(64), unique=True)
    event_id: Mapped[UUID] = mapped_column(ForeignKey("normalized_events.event_id"), index=True)
    source_id: Mapped[UUID] = mapped_column(ForeignKey("ingestion_sources.id"), index=True)
    dataset_id: Mapped[UUID] = mapped_column(index=True)
    run_id: Mapped[UUID] = mapped_column(index=True)
    mode: Mapped[str] = mapped_column(String(8))
    rule_id: Mapped[str] = mapped_column(ForeignKey("rule_deployments.id"))
    rule_version: Mapped[str] = mapped_column(String(32))
    evaluator_version: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(24), default="new", server_default="new", index=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    rule_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)
    event_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)
    event_snapshots: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    reason: Mapped[dict[str, Any]] = mapped_column(JSONB)
    event_sha256: Mapped[str] = mapped_column(String(64))
    risk_score: Mapped[int | None] = mapped_column(Integer)

    __mapper_args__ = {"version_id_col": version}

    @property
    def event_count(self) -> int:
        return len(self.event_snapshots or []) or 1

    @property
    def detection_type(self) -> str:
        return (
            "correlation" if self.evaluator_version.startswith("correlation-") else "single_event"
        )
