"""Append-only identities and source revisions; deployment remains separate."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database import Base, utcnow


class SigmaRule(Base):
    __tablename__ = "sigma_rules"
    __table_args__ = (
        CheckConstraint("detection_id = 'sigma:' || id::text", name="identity_deployment"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True)
    detection_id: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))


class SigmaRuleVersion(Base):
    __tablename__ = "sigma_rule_versions"
    __table_args__ = (
        UniqueConstraint("rule_id", "revision"),
        CheckConstraint("revision BETWEEN 1 AND 20", name="bounded_revision"),
        CheckConstraint("octet_length(definition_yaml) BETWEEN 1 AND 65536", name="bounded_yaml"),
        CheckConstraint("source_sha256 ~ '^[0-9a-f]{64}$'", name="valid_source_hash"),
        CheckConstraint("compiled_sha256 ~ '^[0-9a-f]{64}$'", name="valid_compiled_hash"),
        CheckConstraint("jsonb_typeof(compiled)='object'", name="object_compiled"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    rule_id: Mapped[UUID] = mapped_column(ForeignKey("sigma_rules.id"))
    revision: Mapped[int] = mapped_column(Integer)
    definition_yaml: Mapped[str] = mapped_column(Text)
    source_sha256: Mapped[str] = mapped_column(String(64))
    compiled_sha256: Mapped[str] = mapped_column(String(64))
    evaluator_version: Mapped[str] = mapped_column(String(32))
    compiled: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
