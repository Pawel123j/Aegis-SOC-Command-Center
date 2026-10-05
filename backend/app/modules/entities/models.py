"""Append-only identities, observations and contributor references to immutable evidence."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database import Base, utcnow


class EntityIdentity(Base):
    __tablename__ = "entity_identities"
    __table_args__ = (
        CheckConstraint("kind IN ('host','user','ip','process')", name="valid_kind"),
        CheckConstraint("key_sha256 ~ '^[0-9a-f]{64}$'", name="valid_key_hash"),
        CheckConstraint(
            "jsonb_typeof(canonical_identity)='object' AND "
            "octet_length(canonical_identity::text)<=8192",
            name="bounded_identity",
        ),
        CheckConstraint("char_length(label) BETWEEN 1 AND 256", name="bounded_label"),
        CheckConstraint(
            "(mode='live' AND dataset_id IS NULL AND "
            "run_id='00000000-0000-0000-0000-000000000000'::uuid) OR "
            "(mode='replay' AND dataset_id IS NOT NULL AND "
            "dataset_id<>'00000000-0000-0000-0000-000000000000'::uuid AND "
            "run_id<>'00000000-0000-0000-0000-000000000000'::uuid)",
            name="valid_scope",
        ),
        Index(
            "ix_entities_scope_kind_created",
            "mode",
            "dataset_id",
            "run_id",
            "kind",
            "created_at",
            "id",
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True)
    key_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(16))
    label: Mapped[str] = mapped_column(String(256))
    identity_policy: Mapped[str] = mapped_column(String(32))
    identity_basis: Mapped[str] = mapped_column(String(32))
    canonical_identity: Mapped[dict[str, Any]] = mapped_column(JSONB)
    source_id: Mapped[UUID | None] = mapped_column(ForeignKey("ingestion_sources.id"))
    mode: Mapped[str] = mapped_column(String(8))
    dataset_id: Mapped[UUID | None]
    run_id: Mapped[UUID]
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )


class EntityIndexReceipt(Base):
    __tablename__ = "entity_index_receipts"
    __table_args__ = (
        CheckConstraint("document_sha256 ~ '^[0-9a-f]{64}$'", name="valid_document_hash"),
        CheckConstraint("observation_count BETWEEN 0 AND 8", name="bounded_observations"),
    )
    event_id: Mapped[UUID] = mapped_column(
        ForeignKey("normalized_events.event_id"), primary_key=True
    )
    document_sha256: Mapped[str] = mapped_column(String(64))
    identity_policy: Mapped[str] = mapped_column(String(32))
    observation_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )


class EntityObservation(Base):
    __tablename__ = "entity_observations"
    __table_args__ = (
        CheckConstraint("document_sha256 ~ '^[0-9a-f]{64}$'", name="valid_document_hash"),
        CheckConstraint("char_length(role) BETWEEN 1 AND 32", name="bounded_role"),
        CheckConstraint(
            "jsonb_typeof(attributes)='object' AND octet_length(attributes::text)<=8192",
            name="bounded_attributes",
        ),
        Index("ix_entity_observations_entity_time", "entity_id", "timestamp", "event_id"),
        Index("ix_entity_observations_event", "event_id", "entity_id"),
    )
    entity_id: Mapped[UUID] = mapped_column(ForeignKey("entity_identities.id"), primary_key=True)
    event_id: Mapped[UUID] = mapped_column(
        ForeignKey("entity_index_receipts.event_id"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(32), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    document_sha256: Mapped[str] = mapped_column(String(64))
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB)


class EntityAlertReceipt(Base):
    __tablename__ = "entity_alert_receipts"
    __table_args__ = (
        CheckConstraint("contributor_count BETWEEN 1 AND 100", name="bounded_contributors"),
    )
    alert_id: Mapped[UUID] = mapped_column(ForeignKey("alerts.id"), primary_key=True)
    contributor_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )


class AlertEventReference(Base):
    __tablename__ = "alert_event_references"
    __table_args__ = (
        CheckConstraint("document_sha256 ~ '^[0-9a-f]{64}$'", name="valid_document_hash"),
        Index("ix_alert_event_references_event_alert", "event_id", "alert_id"),
    )
    alert_id: Mapped[UUID] = mapped_column(
        ForeignKey("entity_alert_receipts.alert_id"), primary_key=True
    )
    event_id: Mapped[UUID] = mapped_column(
        ForeignKey("normalized_events.event_id"), primary_key=True
    )
    document_sha256: Mapped[str] = mapped_column(String(64))
