"""Durable bounded correlation with multi-event immutable alert evidence."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_correlation"
down_revision: str | None = "0005_incidents"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

RULE_IDS = (
    "possible_bruteforce_compromise", "repeated_authentication_failures",
    "powershell_then_outbound", "login_then_local_admin_change", "possible_multi_stage_compromise",
)


def upgrade() -> None:
    for rule_id in RULE_IDS:
        op.execute(sa.text("INSERT INTO rule_deployments (id, rule_version) VALUES (:id, '1.0.0')").bindparams(id=rule_id))
    op.add_column("alerts", sa.Column("event_snapshots", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")))
    op.execute("UPDATE alerts SET event_snapshots = jsonb_build_array(jsonb_build_object('event_id', event_id::text, 'event_sha256', event_sha256, 'event_snapshot', event_snapshot))")
    op.create_check_constraint("array_event_snapshots", "alerts", "jsonb_typeof(event_snapshots) = 'array' AND jsonb_array_length(event_snapshots) <= 100")
    op.create_table(
        "correlation_scopes",
        sa.Column("namespace", sa.String(160), primary_key=True),
        sa.Column("watermark", sa.DateTime(timezone=True)),
        sa.Column("sealed_at", sa.DateTime(timezone=True)),
        sa.Column("manifest", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("manifest_sha256", sa.String(64)),
        sa.Column("deployment_snapshot", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("deployment_sha256", sa.String(64)),
        sa.CheckConstraint("jsonb_typeof(manifest) = 'array'", name="array_manifest"),
        sa.CheckConstraint("jsonb_typeof(deployment_snapshot) = 'array'", name="array_deployments"),
    )
    op.create_table(
        "correlation_jobs",
        sa.Column("event_id", sa.Uuid(), sa.ForeignKey("normalized_events.event_id"), primary_key=True),
        sa.Column("namespace", sa.String(160), sa.ForeignKey("correlation_scopes.namespace"), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        *[sa.Column(name, sa.String(64)) for name in ("same_user", "same_host", "same_ip", "same_process")],
        sa.Column("state", sa.String(24), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("processed_at", sa.DateTime(timezone=True)),
        sa.Column("error_code", sa.String(64)),
        sa.Column("evaluated_rules", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.CheckConstraint("state IN ('pending','processed','late','clock_skew','quarantined','incomplete')", name="valid_state"),
        sa.CheckConstraint("jsonb_typeof(evaluated_rules) = 'array'", name="array_rules"),
    )
    op.create_index(op.f("ix_correlation_jobs_state"), "correlation_jobs", ["state"])
    op.create_index("ix_correlation_jobs_scope_time", "correlation_jobs", ["namespace", "timestamp", "event_id"])
    op.create_index("ix_correlation_jobs_auth_keys", "correlation_jobs", ["namespace", "same_user", "same_host", "same_ip", "timestamp", "event_id"])
    op.create_index("ix_correlation_jobs_process_keys", "correlation_jobs", ["namespace", "same_host", "same_process", "timestamp", "event_id"])
    op.create_index("ix_correlation_jobs_user_host", "correlation_jobs", ["namespace", "same_user", "same_host", "timestamp", "event_id"])
    op.execute("""
        CREATE FUNCTION guard_correlation_scope() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.watermark IS NOT NULL AND (NEW.watermark IS NULL OR NEW.watermark < OLD.watermark) THEN
            RAISE EXCEPTION 'correlation watermark cannot decrease' USING ERRCODE = '23514';
          END IF;
          IF OLD.sealed_at IS NOT NULL AND
             (NEW.sealed_at IS DISTINCT FROM OLD.sealed_at OR NEW.manifest IS DISTINCT FROM OLD.manifest
              OR NEW.manifest_sha256 IS DISTINCT FROM OLD.manifest_sha256 OR NEW.watermark IS DISTINCT FROM OLD.watermark
              OR NEW.deployment_snapshot IS DISTINCT FROM OLD.deployment_snapshot OR NEW.deployment_sha256 IS DISTINCT FROM OLD.deployment_sha256) THEN
            RAISE EXCEPTION 'sealed correlation manifest is immutable' USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END $$
    """)
    op.execute("CREATE TRIGGER correlation_scope_guard BEFORE UPDATE ON correlation_scopes FOR EACH ROW EXECUTE FUNCTION guard_correlation_scope()")
    op.execute("GRANT SELECT, INSERT ON correlation_scopes TO aegis_app")
    op.execute("GRANT UPDATE (watermark, sealed_at, manifest, manifest_sha256, deployment_snapshot, deployment_sha256) ON correlation_scopes TO aegis_app")
    op.execute("GRANT SELECT, INSERT ON correlation_jobs TO aegis_app")
    op.execute("GRANT UPDATE (state, processed_at, error_code, evaluated_rules) ON correlation_jobs TO aegis_app")


def downgrade() -> None:
    op.drop_table("correlation_jobs")
    op.drop_table("correlation_scopes")
    op.execute("DROP FUNCTION guard_correlation_scope()")
    op.drop_constraint(op.f("ck_alerts_array_event_snapshots"), "alerts", type_="check")
    op.drop_column("alerts", "event_snapshots")
    # Retain evidence safety: a populated release cannot silently remove its catalog FKs.
    for rule_id in RULE_IDS:
        op.execute(sa.text("DELETE FROM rule_deployments WHERE id = :id").bindparams(id=rule_id))
