"""PostgreSQL queue, immutable versions, attempt history and unique local effects."""

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
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database import Base, utcnow


class Playbook(Base):
    __tablename__ = "playbooks"
    __table_args__ = (
        CheckConstraint("latest_revision BETWEEN 1 AND 20", name="bounded_revision"),
        CheckConstraint(
            "published_revision IS NULL OR published_revision BETWEEN 1 AND latest_revision",
            name="published_revision",
        ),
        CheckConstraint("version >= 1", name="positive_version"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    latest_revision: Mapped[int] = mapped_column(Integer, default=1)
    published_revision: Mapped[int | None] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __mapper_args__ = {"version_id_col": version}


class PlaybookRevision(Base):
    __tablename__ = "playbook_revisions"
    __table_args__ = (
        UniqueConstraint("playbook_id", "revision"),
        CheckConstraint("revision BETWEEN 1 AND 20", name="bounded_revision"),
        CheckConstraint("document_sha256 ~ '^[0-9a-f]{64}$'", name="valid_hash"),
        CheckConstraint(
            "octet_length(canonical_document) BETWEEN 1 AND 16384", name="bounded_document"
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    playbook_id: Mapped[UUID] = mapped_column(ForeignKey("playbooks.id"))
    revision: Mapped[int] = mapped_column(Integer)
    engine_version: Mapped[str] = mapped_column(String(32))
    document: Mapped[dict[str, Any]] = mapped_column(JSONB)
    canonical_document: Mapped[str] = mapped_column(Text)
    document_sha256: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    __table_args__ = (
        UniqueConstraint("requested_by", "idempotency_key"),
        CheckConstraint(
            "state IN ('queued','running','completed','failed','cancelled')", name="valid_state"
        ),
        CheckConstraint("execution_mode='simulation'", name="simulation_only"),
        CheckConstraint(
            "(mode='live' AND data_run_id='00000000-0000-0000-0000-000000000000'::uuid) OR "
            "(mode='replay' AND data_run_id<>'00000000-0000-0000-0000-000000000000'::uuid)",
            name="valid_scope",
        ),
        CheckConstraint("octet_length(context::text) <= 131072", name="bounded_context"),
        CheckConstraint(
            "context_sha256 ~ '^[0-9a-f]{64}$' AND request_sha256 ~ '^[0-9a-f]{64}$'",
            name="valid_hashes",
        ),
        Index("ix_playbook_runs_ready", "state", "next_attempt_at"),
        Index("ix_playbook_runs_scope", "mode", "dataset_id", "data_run_id", "created_at", "id"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    revision_id: Mapped[UUID] = mapped_column(ForeignKey("playbook_revisions.id"))
    alert_id: Mapped[UUID] = mapped_column(ForeignKey("alerts.id"), index=True)
    requested_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    request_sha256: Mapped[str] = mapped_column(String(64))
    replay_of: Mapped[UUID | None] = mapped_column(ForeignKey("playbook_runs.id"))
    execution_mode: Mapped[str] = mapped_column(String(16), default="simulation")
    mode: Mapped[str] = mapped_column(String(8))
    dataset_id: Mapped[UUID] = mapped_column()
    data_run_id: Mapped[UUID] = mapped_column()
    context: Mapped[dict[str, Any]] = mapped_column(JSONB)
    context_sha256: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(16), default="queued")
    cancellation_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PlaybookStep(Base):
    __tablename__ = "playbook_steps"
    __table_args__ = (
        UniqueConstraint("run_id", "position", name="uq_playbook_steps_run_position"),
        UniqueConstraint("run_id", "step_id", name="uq_playbook_steps_run_key"),
        CheckConstraint("position BETWEEN 0 AND 19", name="bounded_position"),
        CheckConstraint("attempts BETWEEN 0 AND 3", name="bounded_attempts"),
        CheckConstraint("state IN ('waiting','running','completed','failed')", name="valid_state"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    run_id: Mapped[UUID] = mapped_column(ForeignKey("playbook_runs.id"))
    position: Mapped[int] = mapped_column(Integer)
    step_id: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(48))
    input_sha256: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(16), default="waiting")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))


class PlaybookAttempt(Base):
    __tablename__ = "playbook_attempts"
    __table_args__ = (
        UniqueConstraint("step_id", "number"),
        CheckConstraint("number BETWEEN 1 AND 3", name="bounded_number"),
        CheckConstraint(
            "outcome IN ('completed','failed','expired','cancelled')", name="valid_outcome"
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    step_id: Mapped[UUID] = mapped_column(ForeignKey("playbook_steps.id"))
    number: Mapped[int] = mapped_column(Integer)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    outcome: Mapped[str] = mapped_column(String(16))
    error_code: Mapped[str | None] = mapped_column(String(64))


class PlaybookEffect(Base):
    __tablename__ = "playbook_effects"
    __table_args__ = (
        CheckConstraint("octet_length(output::text) <= 65536", name="bounded_output"),
        CheckConstraint("output_sha256 ~ '^[0-9a-f]{64}$'", name="valid_hash"),
    )
    step_id: Mapped[UUID] = mapped_column(ForeignKey("playbook_steps.id"), primary_key=True)
    output: Mapped[dict[str, Any]] = mapped_column(JSONB)
    output_sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SoarNotification(Base):
    __tablename__ = "soar_notifications"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    step_id: Mapped[UUID] = mapped_column(ForeignKey("playbook_steps.id"), unique=True)
    recipient_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    message: Mapped[str] = mapped_column(String(512))
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
