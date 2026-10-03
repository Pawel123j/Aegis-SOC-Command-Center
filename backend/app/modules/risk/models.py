"""Append-only calculations; current risk is a guarded SQL projection."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database import Base, utcnow


class RiskCalculation(Base):
    __tablename__ = "risk_calculations"
    __table_args__ = (
        UniqueConstraint(
            "subject_type", "subject_id", "subject_revision", name="uq_risk_subject_revision"
        ),
        CheckConstraint("subject_type IN ('alert','incident')", name="valid_subject"),
        CheckConstraint("subject_revision >= 1", name="positive_revision"),
        CheckConstraint("score BETWEEN 0 AND 100", name="bounded_score"),
        CheckConstraint("level IN ('low','medium','high','critical')", name="valid_level"),
        CheckConstraint(
            "jsonb_typeof(input_snapshot)='object' AND jsonb_typeof(explanation)='object'",
            name="object_snapshots",
        ),
        Index("ix_risk_subject_revision", "subject_type", "subject_id", "subject_revision"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    subject_type: Mapped[str] = mapped_column(String(16))
    subject_id: Mapped[UUID] = mapped_column()
    subject_revision: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    actor_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    trigger: Mapped[str] = mapped_column(String(64))
    previous_id: Mapped[UUID | None] = mapped_column(ForeignKey("risk_calculations.id"))
    policy_version: Mapped[str] = mapped_column(String(32))
    policy_hash: Mapped[str] = mapped_column(String(64))
    input_sha256: Mapped[str] = mapped_column(String(64))
    input_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)
    explanation: Mapped[dict[str, Any]] = mapped_column(JSONB)
    score: Mapped[int] = mapped_column(Integer)
    level: Mapped[str] = mapped_column(String(16))
    mode: Mapped[str] = mapped_column(String(8))
    dataset_id: Mapped[UUID | None] = mapped_column()
    run_id: Mapped[UUID] = mapped_column()
