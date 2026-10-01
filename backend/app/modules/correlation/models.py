"""Durable admission, explicit coverage gaps and scoped event-time progress."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database import Base, utcnow


class CorrelationScope(Base):
    __tablename__ = "correlation_scopes"
    __table_args__ = (
        CheckConstraint("jsonb_typeof(manifest) = 'array'", name="array_manifest"),
        CheckConstraint("jsonb_typeof(deployment_snapshot) = 'array'", name="array_deployments"),
    )
    namespace: Mapped[str] = mapped_column(String(160), primary_key=True)
    watermark: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sealed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    manifest: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    manifest_sha256: Mapped[str | None] = mapped_column(String(64))
    deployment_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    deployment_sha256: Mapped[str | None] = mapped_column(String(64))


class CorrelationJob(Base):
    __tablename__ = "correlation_jobs"
    __table_args__ = (
        CheckConstraint(
            "state IN ('pending','processed','late','clock_skew','quarantined','incomplete')",
            name="valid_state",
        ),
        CheckConstraint("jsonb_typeof(evaluated_rules) = 'array'", name="array_rules"),
        Index("ix_correlation_jobs_scope_time", "namespace", "timestamp", "event_id"),
        Index(
            "ix_correlation_jobs_auth_keys",
            "namespace",
            "same_user",
            "same_host",
            "same_ip",
            "timestamp",
            "event_id",
        ),
        Index(
            "ix_correlation_jobs_process_keys",
            "namespace",
            "same_host",
            "same_process",
            "timestamp",
            "event_id",
        ),
        Index(
            "ix_correlation_jobs_user_host",
            "namespace",
            "same_user",
            "same_host",
            "timestamp",
            "event_id",
        ),
    )
    event_id: Mapped[UUID] = mapped_column(
        ForeignKey("normalized_events.event_id"), primary_key=True
    )
    namespace: Mapped[str] = mapped_column(ForeignKey("correlation_scopes.namespace"))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    same_user: Mapped[str | None] = mapped_column(String(64))
    same_host: Mapped[str | None] = mapped_column(String(64))
    same_ip: Mapped[str | None] = mapped_column(String(64))
    same_process: Mapped[str | None] = mapped_column(String(64))
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
