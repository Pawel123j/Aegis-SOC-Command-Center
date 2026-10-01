"""Immutable normalized snapshots and durable independent projection jobs."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_normalization"
down_revision: str | None = "0002_ingestion"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "normalized_events",
        sa.Column("event_id", sa.Uuid(), sa.ForeignKey("raw_events.id"), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column("parser_version", sa.String(32), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("document_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint("jsonb_typeof(document) = 'object'", name="object_document"),
    )
    op.create_index(op.f("ix_normalized_events_timestamp"), "normalized_events", ["timestamp"])
    op.create_table(
        "pipeline_jobs",
        sa.Column("event_id", sa.Uuid(), sa.ForeignKey("raw_events.id"), primary_key=True),
        sa.Column("state", sa.String(24), nullable=False, server_default="pending"),
        sa.Column("normalization_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("projection_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("lease_token", sa.Uuid()),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_code", sa.String(64)),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "state IN ('pending','normalizing','normalized','projecting','projected','quarantined','projection_failed')",
            name="valid_state",
        ),
        sa.CheckConstraint(
            "normalization_attempts >= 0 AND projection_attempts >= 0", name="nonnegative_attempts"
        ),
        sa.CheckConstraint("version >= 1", name="positive_version"),
    )
    op.create_index(op.f("ix_pipeline_jobs_available_at"), "pipeline_jobs", ["available_at"])
    op.execute("GRANT SELECT, INSERT ON normalized_events TO aegis_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON pipeline_jobs TO aegis_app")


def downgrade() -> None:
    op.drop_table("pipeline_jobs")
    op.drop_table("normalized_events")
