"""Local IOC revisions and immutable per-event matching receipts."""

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
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database import Base, utcnow


class IOCIdentity(Base):
    __tablename__ = "ioc_identities"
    __table_args__ = (
        UniqueConstraint("kind", "canonical_value"),
        CheckConstraint("kind IN ('ip','domain','url','hash')", name="valid_kind"),
        CheckConstraint("char_length(canonical_value) BETWEEN 1 AND 2048", name="bounded_value"),
        CheckConstraint(
            "(version=0 AND current_revision_id IS NULL) OR "
            "(version BETWEEN 1 AND 50 AND current_revision_id IS NOT NULL)",
            name="valid_pointer",
        ),
        Index("ix_ioc_identities_created", "created_at", "id"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    kind: Mapped[str] = mapped_column(String(16))
    canonical_value: Mapped[str] = mapped_column(String(2048))
    normalization_version: Mapped[str] = mapped_column(String(32))
    current_revision_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("ioc_revisions.id", use_alter=True, name="fk_ioc_current_revision")
    )
    version: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))


class IOCRevision(Base):
    __tablename__ = "ioc_revisions"
    __table_args__ = (
        UniqueConstraint("ioc_id", "revision"),
        CheckConstraint("revision BETWEEN 1 AND 50", name="bounded_revision"),
        CheckConstraint("document_sha256 ~ '^[0-9a-f]{64}$'", name="valid_document_hash"),
        CheckConstraint(
            "jsonb_typeof(document)='object' AND octet_length(document::text)<=32768",
            name="bounded_document",
        ),
        CheckConstraint(
            "octet_length(canonical_document) BETWEEN 1 AND 32768", name="bounded_canonical"
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    ioc_id: Mapped[UUID] = mapped_column(ForeignKey("ioc_identities.id"))
    revision: Mapped[int] = mapped_column(Integer)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB)
    canonical_document: Mapped[str] = mapped_column(Text)
    document_sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))


class IntEventReceipt(Base):
    __tablename__ = "int_event_receipts"
    __table_args__ = (
        CheckConstraint("document_sha256 ~ '^[0-9a-f]{64}$'", name="valid_document_hash"),
        CheckConstraint("match_count BETWEEN 0 AND 32", name="bounded_matches"),
        CheckConstraint(
            "(mode='live' AND dataset_id IS NULL AND "
            "run_id='00000000-0000-0000-0000-000000000000'::uuid) OR "
            "(mode='replay' AND dataset_id IS NOT NULL AND "
            "dataset_id<>'00000000-0000-0000-0000-000000000000'::uuid AND "
            "run_id<>'00000000-0000-0000-0000-000000000000'::uuid)",
            name="valid_scope",
        ),
    )
    event_id: Mapped[UUID] = mapped_column(
        ForeignKey("normalized_events.event_id"), primary_key=True
    )
    document_sha256: Mapped[str] = mapped_column(String(64))
    normalization_version: Mapped[str] = mapped_column(String(32))
    mode: Mapped[str] = mapped_column(String(8))
    dataset_id: Mapped[UUID | None]
    run_id: Mapped[UUID]
    match_count: Mapped[int] = mapped_column(Integer)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )


class IntEventMatch(Base):
    __tablename__ = "int_event_matches"
    __table_args__ = (
        UniqueConstraint("event_id", "revision_id", "field"),
        CheckConstraint("char_length(field) BETWEEN 1 AND 128", name="bounded_field"),
        CheckConstraint(
            "char_length(observed_value) BETWEEN 1 AND 8192 AND "
            "char_length(canonical_value) BETWEEN 1 AND 2048",
            name="bounded_value",
        ),
        CheckConstraint("revision_snapshot_sha256 ~ '^[0-9a-f]{64}$'", name="valid_snapshot_hash"),
        CheckConstraint(
            "jsonb_typeof(revision_snapshot)='object' AND "
            "octet_length(revision_snapshot::text)<=32768",
            name="bounded_snapshot",
        ),
        Index("ix_int_event_matches_ioc_event", "ioc_id", "event_id"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    event_id: Mapped[UUID] = mapped_column(ForeignKey("int_event_receipts.event_id"))
    ioc_id: Mapped[UUID] = mapped_column(ForeignKey("ioc_identities.id"))
    revision_id: Mapped[UUID] = mapped_column(ForeignKey("ioc_revisions.id"))
    field: Mapped[str] = mapped_column(String(128))
    observed_value: Mapped[str] = mapped_column(String(8192))
    canonical_value: Mapped[str] = mapped_column(String(2048))
    revision_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)
    revision_snapshot_sha256: Mapped[str] = mapped_column(String(64))
