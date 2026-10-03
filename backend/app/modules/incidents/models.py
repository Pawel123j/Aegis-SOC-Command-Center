"""Mutable case disposition, immutable evidence references and append-only history."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database import Base, utcnow


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('new','investigating','contained','resolved','closed')", name="valid_status"
        ),
        CheckConstraint("severity IN ('low','medium','high','critical')", name="valid_severity"),
        CheckConstraint(
            "(mode = 'live' AND dataset_id IS NULL AND "
            "run_id = '00000000-0000-0000-0000-000000000000'::uuid) OR "
            "(mode = 'replay' AND dataset_id IS NOT NULL AND "
            "run_id <> '00000000-0000-0000-0000-000000000000'::uuid)",
            name="valid_scope",
        ),
        CheckConstraint("version >= 1", name="positive_version"),
        CheckConstraint("risk_score IS NULL OR risk_score BETWEEN 0 AND 100", name="bounded_risk"),
        CheckConstraint(
            "(risk_score IS NULL AND risk_level IS NULL AND risk_calculation_id IS NULL) OR "
            "(risk_score IS NOT NULL AND risk_level IS NOT NULL "
            "AND risk_level IN ('low','medium','high','critical') "
            "AND risk_calculation_id IS NOT NULL)",
            name="consistent_risk_projection",
        ),
        CheckConstraint(
            "confidence IS NULL OR confidence BETWEEN 0 AND 100", name="bounded_confidence"
        ),
        CheckConstraint("alert_count BETWEEN 0 AND 100", name="bounded_alert_count"),
        CheckConstraint(
            "(first_seen IS NULL AND last_seen IS NULL AND alert_count = 0) OR "
            "(first_seen IS NOT NULL AND last_seen IS NOT NULL "
            "AND last_seen >= first_seen AND alert_count > 0)",
            name="consistent_event_range",
        ),
        CheckConstraint(
            "jsonb_typeof(tags) = 'array' AND jsonb_array_length(tags) <= 20", name="array_tags"
        ),
        CheckConstraint(
            "jsonb_typeof(related_users) = 'array' AND jsonb_typeof(related_hosts) = 'array' AND "
            "jsonb_typeof(related_ip_addresses) = 'array' "
            "AND jsonb_typeof(mitre_techniques) = 'array' "
            "AND jsonb_typeof(dataset_ids) = 'array'",
            name="array_entities",
        ),
        Index("ix_incidents_created_at_id", "created_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    automatic_alert_id: Mapped[UUID | None] = mapped_column(ForeignKey("alerts.id"), unique=True)
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24), default="new", server_default="new", index=True)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    risk_level: Mapped[str | None] = mapped_column(String(16))
    risk_calculation_id: Mapped[UUID | None] = mapped_column(ForeignKey("risk_calculations.id"))
    confidence: Mapped[int | None] = mapped_column(Integer)
    mode: Mapped[str] = mapped_column(String(8))
    dataset_id: Mapped[UUID | None] = mapped_column(index=True)
    run_id: Mapped[UUID] = mapped_column(index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    updated_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    owner_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    alert_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default=text("'[]'::jsonb"))
    dataset_ids: Mapped[list[str]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    related_users: Mapped[list[str]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    related_hosts: Mapped[list[str]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    related_ip_addresses: Mapped[list[str]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    mitre_techniques: Mapped[list[str]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )

    __mapper_args__ = {"version_id_col": version}


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    __table_args__ = (
        UniqueConstraint("incident_id", "alert_id", name="uq_incident_alerts_incident_alert"),
        CheckConstraint(
            "(active AND detached_at IS NULL) OR (NOT active AND detached_at IS NOT NULL)",
            name="consistent_attachment",
        ),
        Index("ix_incident_alerts_incident_linked", "incident_id", "linked_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id"), index=True)
    alert_id: Mapped[UUID] = mapped_column(ForeignKey("alerts.id"), index=True)
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    linked_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    detached_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    detached_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))


class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"
    __table_args__ = (
        CheckConstraint("jsonb_typeof(data) = 'object'", name="object_data"),
        Index("ix_incident_timeline_incident_time", "incident_id", "occurred_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id"))
    kind: Mapped[str] = mapped_column(String(32))
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    actor_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    actor: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)


class IncidentNote(Base):
    __tablename__ = "incident_notes"
    __table_args__ = (
        CheckConstraint("char_length(body) BETWEEN 1 AND 5000", name="bounded_body"),
        Index("ix_incident_notes_incident_time", "incident_id", "created_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id"))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    author_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    author: Mapped[dict[str, Any]] = mapped_column(JSONB)


class IncidentCreateReceipt(Base):
    __tablename__ = "incident_create_receipts"

    actor_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), primary_key=True)
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    body_sha256: Mapped[str] = mapped_column(String(64))
    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
