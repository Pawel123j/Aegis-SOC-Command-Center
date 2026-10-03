"""Append-only association snapshots and bounded normalized aggregate keys."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database import Base, utcnow


class AlertMitreSnapshot(Base):
    __tablename__ = "alert_mitre_snapshots"
    __table_args__ = (
        CheckConstraint("status IN ('mapped','unmapped')", name="valid_status"),
        CheckConstraint("catalogue_hash ~ '^[0-9a-f]{64}$'", name="valid_catalogue_hash"),
        CheckConstraint("mapping_hash ~ '^[0-9a-f]{64}$'", name="valid_mapping_hash"),
        CheckConstraint("input_sha256 ~ '^[0-9a-f]{64}$'", name="valid_input_hash"),
        CheckConstraint("snapshot_sha256 ~ '^[0-9a-f]{64}$'", name="valid_snapshot_hash"),
        CheckConstraint(
            "jsonb_typeof(document)='object' AND "
            "document->'techniques' IS NOT NULL AND "
            "jsonb_typeof(document->'techniques')='array' AND "
            "jsonb_array_length(document->'techniques') <= 20",
            name="bounded_document",
        ),
        CheckConstraint(
            "(status='mapped' AND jsonb_array_length(document->'techniques')>0) OR "
            "(status='unmapped' AND jsonb_array_length(document->'techniques')=0)",
            name="consistent_status",
        ),
    )
    alert_id: Mapped[UUID] = mapped_column(ForeignKey("alerts.id"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    status: Mapped[str] = mapped_column(String(16))
    catalogue_version: Mapped[str] = mapped_column(String(32))
    catalogue_hash: Mapped[str] = mapped_column(String(64))
    mapping_version: Mapped[str] = mapped_column(String(32))
    mapping_hash: Mapped[str] = mapped_column(String(64))
    input_sha256: Mapped[str] = mapped_column(String(64))
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    document: Mapped[dict[str, Any]] = mapped_column(JSONB)


class AlertMitreMapping(Base):
    __tablename__ = "alert_mitre_mappings"
    __table_args__ = (
        CheckConstraint("technique_id ~ '^T[0-9]{4}(\\.[0-9]{3})?$'", name="valid_technique"),
        CheckConstraint("tactic_id ~ '^TA[0-9]{4}$'", name="valid_tactic"),
        Index("ix_alert_mitre_technique", "technique_id", "alert_id"),
        Index("ix_alert_mitre_tactic", "tactic_id", "alert_id"),
    )
    alert_id: Mapped[UUID] = mapped_column(
        ForeignKey("alert_mitre_snapshots.alert_id"), primary_key=True
    )
    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    tactic_id: Mapped[str] = mapped_column(String(8), primary_key=True)
