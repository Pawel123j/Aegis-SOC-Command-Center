"""Durable admission, input ordering, leases and bounded storage accounting."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database import Base, utcnow

LIVE_RUN_ID = UUID(int=0)


class IngestionSource(Base):
    __tablename__ = "ingestion_sources"
    __table_args__ = (
        CheckConstraint("mode IN ('live', 'replay')", name="valid_mode"),
        CheckConstraint(
            "mode <> 'live' OR run_id = '00000000-0000-0000-0000-000000000000'::uuid",
            name="live_run",
        ),
        CheckConstraint(
            "jsonb_typeof(source_types) = 'array' AND jsonb_array_length(source_types) > 0",
            name="nonempty_source_types",
        ),
        CheckConstraint("version >= 1", name="positive_version"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    dataset_id: Mapped[UUID] = mapped_column(default=uuid4)
    mode: Mapped[str] = mapped_column(String(8), default="live", server_default="live")
    run_id: Mapped[UUID] = mapped_column(default=lambda: LIVE_RUN_ID)
    source_types: Mapped[list[str]] = mapped_column(JSONB)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC", server_default="UTC")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    version: Mapped[int] = mapped_column(Integer, default=1, server_default=text("1"))

    __mapper_args__ = {"version_id_col": version}


class SourceCredential(Base):
    __tablename__ = "source_credentials"
    __table_args__ = (
        CheckConstraint(
            "jsonb_typeof(scopes) = 'array' AND jsonb_array_length(scopes) > 0 "
            'AND scopes <@ \'["events:write","events:status"]\'::jsonb',
            name="valid_scopes",
        ),
        CheckConstraint("expires_at > created_at", name="positive_lifetime"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    source_id: Mapped[UUID] = mapped_column(ForeignKey("ingestion_sources.id"), index=True)
    secret_hash: Mapped[str] = mapped_column(String(64), unique=True)
    scopes: Mapped[list[str]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IngestionBatch(Base):
    __tablename__ = "ingestion_batches"
    __table_args__ = (
        UniqueConstraint(
            "source_id",
            "dataset_id",
            "mode",
            "run_id",
            "idempotency_key",
            name="uq_ingestion_batches_scope_key",
        ),
        CheckConstraint("mode IN ('live', 'replay')", name="valid_mode"),
        CheckConstraint(
            "accepted_count BETWEEN 1 AND 500 AND created_count >= 0 "
            "AND duplicate_count >= 0 AND accepted_count = created_count + duplicate_count",
            name="consistent_counts",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    source_id: Mapped[UUID] = mapped_column(ForeignKey("ingestion_sources.id"), index=True)
    dataset_id: Mapped[UUID]
    mode: Mapped[str] = mapped_column(String(8))
    run_id: Mapped[UUID]
    idempotency_key: Mapped[str] = mapped_column(String(128))
    payload_hash: Mapped[str] = mapped_column(String(64))
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    request_id: Mapped[str] = mapped_column(String(64))
    accepted_count: Mapped[int] = mapped_column(Integer)
    created_count: Mapped[int] = mapped_column(Integer)
    duplicate_count: Mapped[int] = mapped_column(Integer)


class RawEvent(Base):
    __tablename__ = "raw_events"
    __table_args__ = (
        UniqueConstraint(
            "source_id",
            "dataset_id",
            "mode",
            "run_id",
            "source_event_id",
            name="uq_raw_events_scope_event",
        ),
        CheckConstraint("mode IN ('live', 'replay')", name="valid_mode"),
        CheckConstraint("payload_bytes > 0", name="positive_payload_bytes"),
        CheckConstraint("jsonb_typeof(envelope) = 'object'", name="object_envelope"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    source_id: Mapped[UUID] = mapped_column(ForeignKey("ingestion_sources.id"), index=True)
    dataset_id: Mapped[UUID]
    mode: Mapped[str] = mapped_column(String(8))
    run_id: Mapped[UUID]
    source_event_id: Mapped[str | None] = mapped_column(String(128))
    source_type: Mapped[str] = mapped_column(String(32))
    envelope: Mapped[dict[str, Any]] = mapped_column(JSONB)
    payload_hash: Mapped[str] = mapped_column(String(64))
    payload_bytes: Mapped[int] = mapped_column(Integer)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()"), index=True
    )
    request_id: Mapped[str] = mapped_column(String(64))


class BatchEvent(Base):
    __tablename__ = "batch_events"
    __table_args__ = (CheckConstraint("position BETWEEN 0 AND 499", name="valid_position"),)

    batch_id: Mapped[UUID] = mapped_column(ForeignKey("ingestion_batches.id"), primary_key=True)
    position: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[UUID] = mapped_column(ForeignKey("raw_events.id"), index=True)


class OutboxJob(Base):
    __tablename__ = "outbox_jobs"
    __table_args__ = (
        CheckConstraint(
            "state IN ('pending', 'processing', 'staged', 'quarantined')", name="valid_state"
        ),
        CheckConstraint("generation >= 1", name="positive_generation"),
        CheckConstraint("attempts >= 0 AND dispatch_attempts >= 0", name="nonnegative_attempts"),
    )

    event_id: Mapped[UUID] = mapped_column(ForeignKey("raw_events.id"), primary_key=True)
    generation: Mapped[int] = mapped_column(Integer, default=1, server_default=text("1"))
    state: Mapped[str] = mapped_column(
        String(16), default="pending", server_default="pending", index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    dispatch_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()"), index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(64))
    dispatch_token: Mapped[UUID | None]
    dispatch_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    worker_token: Mapped[UUID | None]
    worker_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IngestCapacity(Base):
    __tablename__ = "ingest_capacity"
    __table_args__ = (
        CheckConstraint("id = 1", name="singleton"),
        CheckConstraint(
            "event_count >= 0 AND byte_count >= 0 AND receipt_count >= 0", name="nonnegative_counts"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_count: Mapped[int] = mapped_column(BigInteger, default=0, server_default=text("0"))
    byte_count: Mapped[int] = mapped_column(BigInteger, default=0, server_default=text("0"))
    receipt_count: Mapped[int] = mapped_column(BigInteger, default=0, server_default=text("0"))
