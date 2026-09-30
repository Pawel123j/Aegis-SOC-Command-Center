"""Durable source-scoped admission, raw inbox, outbox and capacity accounting.

Revision ID: 0002_ingestion
Revises: 0001_foundation
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_ingestion"
down_revision: str | None = "0001_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ingestion_sources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("dataset_id", sa.Uuid(), nullable=False),
        sa.Column("mode", sa.String(8), server_default="live", nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("source_types", postgresql.JSONB(), nullable=False),
        sa.Column("timezone", sa.String(64), server_default="UTC", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.CheckConstraint(
            "mode IN ('live', 'replay')", name=op.f("ck_ingestion_sources_valid_mode")
        ),
        sa.CheckConstraint(
            "mode <> 'live' OR run_id = '00000000-0000-0000-0000-000000000000'::uuid",
            name=op.f("ck_ingestion_sources_live_run"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(source_types) = 'array' AND jsonb_array_length(source_types) > 0",
            name=op.f("ck_ingestion_sources_nonempty_source_types"),
        ),
        sa.CheckConstraint("version >= 1", name=op.f("ck_ingestion_sources_positive_version")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ingestion_sources")),
        sa.UniqueConstraint("name", name=op.f("uq_ingestion_sources_name")),
    )
    op.create_table(
        "source_credentials",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("secret_hash", sa.String(64), nullable=False),
        sa.Column("scopes", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "jsonb_typeof(scopes) = 'array' AND jsonb_array_length(scopes) > 0 "
            'AND scopes <@ \'["events:write","events:status"]\'::jsonb',
            name=op.f("ck_source_credentials_valid_scopes"),
        ),
        sa.CheckConstraint(
            "expires_at > created_at", name=op.f("ck_source_credentials_positive_lifetime")
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["ingestion_sources.id"],
            name=op.f("fk_source_credentials_source_id_ingestion_sources"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_source_credentials")),
        sa.UniqueConstraint("secret_hash", name=op.f("uq_source_credentials_secret_hash")),
    )
    op.create_index(op.f("ix_source_credentials_source_id"), "source_credentials", ["source_id"])
    op.create_index(op.f("ix_source_credentials_expires_at"), "source_credentials", ["expires_at"])
    op.create_table(
        "ingestion_batches",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("dataset_id", sa.Uuid(), nullable=False),
        sa.Column("mode", sa.String(8), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column("accepted_count", sa.Integer(), nullable=False),
        sa.Column("created_count", sa.Integer(), nullable=False),
        sa.Column("duplicate_count", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "mode IN ('live', 'replay')", name=op.f("ck_ingestion_batches_valid_mode")
        ),
        sa.CheckConstraint(
            "accepted_count BETWEEN 1 AND 500 AND created_count >= 0 "
            "AND duplicate_count >= 0 AND accepted_count = created_count + duplicate_count",
            name=op.f("ck_ingestion_batches_consistent_counts"),
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["ingestion_sources.id"],
            name=op.f("fk_ingestion_batches_source_id_ingestion_sources"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ingestion_batches")),
        sa.UniqueConstraint(
            "source_id",
            "dataset_id",
            "mode",
            "run_id",
            "idempotency_key",
            name="uq_ingestion_batches_scope_key",
        ),
    )
    op.create_index(op.f("ix_ingestion_batches_source_id"), "ingestion_batches", ["source_id"])
    op.create_table(
        "raw_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("dataset_id", sa.Uuid(), nullable=False),
        sa.Column("mode", sa.String(8), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("source_event_id", sa.String(128), nullable=True),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("envelope", postgresql.JSONB(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("payload_bytes", sa.Integer(), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.CheckConstraint("mode IN ('live', 'replay')", name=op.f("ck_raw_events_valid_mode")),
        sa.CheckConstraint("payload_bytes > 0", name=op.f("ck_raw_events_positive_payload_bytes")),
        sa.CheckConstraint(
            "jsonb_typeof(envelope) = 'object'", name=op.f("ck_raw_events_object_envelope")
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["ingestion_sources.id"],
            name=op.f("fk_raw_events_source_id_ingestion_sources"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_raw_events")),
        sa.UniqueConstraint(
            "source_id",
            "dataset_id",
            "mode",
            "run_id",
            "source_event_id",
            name="uq_raw_events_scope_event",
        ),
    )
    op.create_index(op.f("ix_raw_events_source_id"), "raw_events", ["source_id"])
    op.create_index(op.f("ix_raw_events_received_at"), "raw_events", ["received_at"])
    op.create_table(
        "batch_events",
        sa.Column("batch_id", sa.Uuid(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "position BETWEEN 0 AND 499", name=op.f("ck_batch_events_valid_position")
        ),
        sa.ForeignKeyConstraint(
            ["batch_id"],
            ["ingestion_batches.id"],
            name=op.f("fk_batch_events_batch_id_ingestion_batches"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["raw_events.id"], name=op.f("fk_batch_events_event_id_raw_events")
        ),
        sa.PrimaryKeyConstraint("batch_id", "position", name=op.f("pk_batch_events")),
    )
    op.create_index(op.f("ix_batch_events_event_id"), "batch_events", ["event_id"])
    op.create_table(
        "outbox_jobs",
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("generation", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("state", sa.String(16), server_default="pending", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("dispatch_attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(64), nullable=True),
        sa.Column("dispatch_token", sa.Uuid(), nullable=True),
        sa.Column("dispatch_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("worker_token", sa.Uuid(), nullable=True),
        sa.Column("worker_until", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('pending', 'processing', 'staged', 'quarantined')",
            name=op.f("ck_outbox_jobs_valid_state"),
        ),
        sa.CheckConstraint("generation >= 1", name=op.f("ck_outbox_jobs_positive_generation")),
        sa.CheckConstraint(
            "attempts >= 0 AND dispatch_attempts >= 0",
            name=op.f("ck_outbox_jobs_nonnegative_attempts"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["raw_events.id"], name=op.f("fk_outbox_jobs_event_id_raw_events")
        ),
        sa.PrimaryKeyConstraint("event_id", name=op.f("pk_outbox_jobs")),
    )
    op.create_index(op.f("ix_outbox_jobs_state"), "outbox_jobs", ["state"])
    op.create_index(op.f("ix_outbox_jobs_available_at"), "outbox_jobs", ["available_at"])
    op.create_index(op.f("ix_outbox_jobs_created_at"), "outbox_jobs", ["created_at"])
    op.create_table(
        "ingest_capacity",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_count", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("receipt_count", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.CheckConstraint("id = 1", name=op.f("ck_ingest_capacity_singleton")),
        sa.CheckConstraint(
            "event_count >= 0 AND byte_count >= 0 AND receipt_count >= 0",
            name=op.f("ck_ingest_capacity_nonnegative_counts"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ingest_capacity")),
    )
    op.execute(
        "INSERT INTO ingest_capacity (id, event_count, byte_count, receipt_count) "
        "VALUES (1, 0, 0, 0)"
    )
    op.execute(
        "REVOKE ALL ON TABLE ingestion_sources, source_credentials, ingestion_batches, "
        "raw_events, batch_events, outbox_jobs, ingest_capacity FROM PUBLIC, aegis_app"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON TABLE ingestion_sources, source_credentials, "
        "outbox_jobs TO aegis_app"
    )
    op.execute(
        "GRANT SELECT, INSERT ON TABLE ingestion_batches, raw_events, batch_events TO aegis_app"
    )
    op.execute("GRANT SELECT, UPDATE ON TABLE ingest_capacity TO aegis_app")


def downgrade() -> None:
    op.drop_table("ingest_capacity")
    op.drop_table("outbox_jobs")
    op.drop_table("batch_events")
    op.drop_table("raw_events")
    op.drop_table("ingestion_batches")
    op.drop_table("source_credentials")
    op.drop_table("ingestion_sources")
