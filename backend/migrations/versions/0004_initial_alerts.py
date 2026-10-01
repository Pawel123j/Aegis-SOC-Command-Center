"""Initial fixed per-event rules, atomic alert evidence and evaluation checkpoints."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_initial_alerts"
down_revision: str | None = "0003_normalization"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    rules = op.create_table(
        "rule_deployments",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("rule_version", sa.String(32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("updated_by", sa.Uuid(), sa.ForeignKey("users.id")),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint("version >= 1", name="positive_version"),
    )
    # Historical migrations must not import a catalog that can change in a later release.
    op.bulk_insert(
        rules,
        [
            {"id": rule_id, "rule_version": "1.0.0"}
            for rule_id in (
                "powershell-suspicious-command",
                "linux-root-session",
                "windows-local-admin-member-added",
            )
        ],
    )
    op.create_table(
        "detection_jobs",
        sa.Column(
            "event_id", sa.Uuid(), sa.ForeignKey("normalized_events.event_id"), primary_key=True
        ),
        sa.Column("state", sa.String(24), nullable=False, server_default="pending"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("processed_at", sa.DateTime(timezone=True)),
        sa.Column("error_code", sa.String(64)),
        sa.Column(
            "evaluated_rules",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.CheckConstraint("state IN ('pending','processed','quarantined')", name="valid_state"),
        sa.CheckConstraint("jsonb_typeof(evaluated_rules) = 'array'", name="array_rules"),
    )
    op.create_index(op.f("ix_detection_jobs_state"), "detection_jobs", ["state"])
    op.create_table(
        "alerts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("detection_key", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "event_id", sa.Uuid(), sa.ForeignKey("normalized_events.event_id"), nullable=False
        ),
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ingestion_sources.id"), nullable=False),
        sa.Column("dataset_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("mode", sa.String(8), nullable=False),
        sa.Column("rule_id", sa.String(64), sa.ForeignKey("rule_deployments.id"), nullable=False),
        sa.Column("rule_version", sa.String(32), nullable=False),
        sa.Column("evaluator_version", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="new"),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("acknowledged_by", sa.Uuid(), sa.ForeignKey("users.id")),
        sa.Column("updated_by", sa.Uuid(), sa.ForeignKey("users.id")),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("rule_snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("event_snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("reason", postgresql.JSONB(), nullable=False),
        sa.Column("event_sha256", sa.String(64), nullable=False),
        sa.Column("risk_score", sa.Integer()),
        sa.CheckConstraint(
            "status IN ('new','acknowledged','false_positive','resolved')", name="valid_status"
        ),
        sa.CheckConstraint(
            "severity IN ('informational','low','medium','high','critical')", name="valid_severity"
        ),
        sa.CheckConstraint("mode IN ('live','replay')", name="valid_mode"),
        sa.CheckConstraint("version >= 1", name="positive_version"),
        sa.CheckConstraint(
            "risk_score IS NULL OR risk_score BETWEEN 0 AND 100", name="bounded_risk"
        ),
        sa.CheckConstraint(
            "jsonb_typeof(rule_snapshot) = 'object' AND jsonb_typeof(event_snapshot) = 'object' AND jsonb_typeof(reason) = 'object'",
            name="object_evidence",
        ),
    )
    for column in ("event_id", "source_id", "dataset_id", "run_id", "status"):
        op.create_index(op.f(f"ix_alerts_{column}"), "alerts", [column])
    op.create_index("ix_alerts_created_at_id", "alerts", ["created_at", "id"])
    op.execute("GRANT SELECT ON rule_deployments TO aegis_app")
    op.execute(
        "GRANT UPDATE (enabled, updated_at, updated_by, version) ON rule_deployments TO aegis_app"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE ON detection_jobs TO aegis_app")
    op.execute("GRANT SELECT, INSERT ON alerts TO aegis_app")
    op.execute(
        "GRANT UPDATE (status, acknowledged_at, acknowledged_by, updated_at, updated_by, version) ON alerts TO aegis_app"
    )


def downgrade() -> None:
    op.drop_table("alerts")
    op.drop_table("detection_jobs")
    op.drop_table("rule_deployments")
