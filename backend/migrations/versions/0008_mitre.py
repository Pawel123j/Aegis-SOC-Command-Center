"""Append-only ATT&CK references, safe aggregate indexes, no historical rewriting."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_mitre"
down_revision: str | None = "0007_risk"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "alert_mitre_snapshots",
        sa.Column("alert_id", sa.Uuid(), sa.ForeignKey("alerts.id"), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("catalogue_version", sa.String(32), nullable=False),
        sa.Column("catalogue_hash", sa.String(64), nullable=False),
        sa.Column("mapping_version", sa.String(32), nullable=False),
        sa.Column("mapping_hash", sa.String(64), nullable=False),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.CheckConstraint("status IN ('mapped','unmapped')", name="valid_status"),
        sa.CheckConstraint("catalogue_hash ~ '^[0-9a-f]{64}$'", name="valid_catalogue_hash"),
        sa.CheckConstraint("mapping_hash ~ '^[0-9a-f]{64}$'", name="valid_mapping_hash"),
        sa.CheckConstraint("input_sha256 ~ '^[0-9a-f]{64}$'", name="valid_input_hash"),
        sa.CheckConstraint("snapshot_sha256 ~ '^[0-9a-f]{64}$'", name="valid_snapshot_hash"),
        sa.CheckConstraint("jsonb_typeof(document)='object' AND document->'techniques' IS NOT NULL AND jsonb_typeof(document->'techniques')='array' AND jsonb_array_length(document->'techniques') <= 20", name="bounded_document"),
        sa.CheckConstraint("(status='mapped' AND jsonb_array_length(document->'techniques')>0) OR (status='unmapped' AND jsonb_array_length(document->'techniques')=0)", name="consistent_status"),
    )
    op.create_table(
        "alert_mitre_mappings",
        sa.Column("alert_id", sa.Uuid(), sa.ForeignKey("alert_mitre_snapshots.alert_id"), primary_key=True),
        sa.Column("technique_id", sa.String(16), primary_key=True),
        sa.Column("tactic_id", sa.String(8), primary_key=True),
        sa.CheckConstraint("technique_id ~ '^T[0-9]{4}(\\.[0-9]{3})?$'", name="valid_technique"),
        sa.CheckConstraint("tactic_id ~ '^TA[0-9]{4}$'", name="valid_tactic"),
    )
    op.create_index("ix_alert_mitre_technique", "alert_mitre_mappings", ["technique_id", "alert_id"])
    op.create_index("ix_alert_mitre_tactic", "alert_mitre_mappings", ["tactic_id", "alert_id"])
    op.create_index("ix_alerts_mitre_live_time", "alerts", ["mode", "event_timestamp", "id"])
    op.create_index("ix_alerts_mitre_replay_time", "alerts", ["mode", "dataset_id", "run_id", "event_timestamp", "id"])
    op.execute("GRANT SELECT, INSERT ON alert_mitre_snapshots, alert_mitre_mappings TO aegis_app")
    op.execute("""
CREATE FUNCTION public.aegis_validate_mitre_mapping() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog, public AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.alert_mitre_snapshots s,
      jsonb_array_elements(s.document->'techniques') t,
      jsonb_array_elements(t->'tactics') tactic
    WHERE s.alert_id=NEW.alert_id AND s.status='mapped'
      AND t->>'id'=NEW.technique_id AND tactic->>'id'=NEW.tactic_id
  ) THEN RAISE EXCEPTION 'MITRE normalized mapping does not match frozen snapshot'
    USING ERRCODE='23514'; END IF;
  RETURN NEW;
END $$
""")
    op.execute("REVOKE ALL ON FUNCTION public.aegis_validate_mitre_mapping() FROM PUBLIC")
    op.execute("CREATE TRIGGER validate_mitre_mapping BEFORE INSERT ON public.alert_mitre_mappings FOR EACH ROW EXECUTE FUNCTION public.aegis_validate_mitre_mapping()")


def downgrade() -> None:
    op.execute("DO $$ BEGIN IF EXISTS (SELECT 1 FROM public.alert_mitre_snapshots) THEN RAISE EXCEPTION 'MITRE history exists; downgrade would destroy immutable references' USING ERRCODE='23514'; END IF; END $$")
    op.drop_index("ix_alerts_mitre_replay_time", table_name="alerts")
    op.drop_index("ix_alerts_mitre_live_time", table_name="alerts")
    op.drop_table("alert_mitre_mappings")
    op.execute("DROP FUNCTION public.aegis_validate_mitre_mapping()")
    op.drop_table("alert_mitre_snapshots")
