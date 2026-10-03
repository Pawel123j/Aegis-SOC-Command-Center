"""Immutable assessments and restricted, scope-checked current-score projection."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_risk"
down_revision: str | None = "0006_correlation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "risk_calculations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("subject_type", sa.String(16), nullable=False),
        sa.Column("subject_id", sa.Uuid(), nullable=False),
        sa.Column("subject_revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("actor_id", sa.Uuid(), sa.ForeignKey("users.id")),
        sa.Column("trigger", sa.String(64), nullable=False),
        sa.Column("previous_id", sa.Uuid(), sa.ForeignKey("risk_calculations.id")),
        sa.Column("policy_version", sa.String(32), nullable=False),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("input_snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("explanation", postgresql.JSONB(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column("mode", sa.String(8), nullable=False),
        sa.Column("dataset_id", sa.Uuid()),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.UniqueConstraint("subject_type", "subject_id", "subject_revision", name="uq_risk_subject_revision"),
        sa.CheckConstraint("subject_type IN ('alert','incident')", name="valid_subject"),
        sa.CheckConstraint("subject_revision >= 1", name="positive_revision"),
        sa.CheckConstraint("score BETWEEN 0 AND 100", name="bounded_score"),
        sa.CheckConstraint("level IN ('low','medium','high','critical')", name="valid_level"),
        sa.CheckConstraint("jsonb_typeof(input_snapshot)='object' AND jsonb_typeof(explanation)='object'", name="object_snapshots"),
    )
    op.create_index("ix_risk_subject_revision", "risk_calculations", ["subject_type", "subject_id", "subject_revision"])
    op.execute("GRANT SELECT, INSERT ON risk_calculations TO aegis_app")
    for table in ("alerts", "incidents"):
        op.add_column(table, sa.Column("risk_level", sa.String(16)))
        op.add_column(table, sa.Column("risk_calculation_id", sa.Uuid(), sa.ForeignKey("risk_calculations.id")))
        op.create_check_constraint("consistent_risk_projection", table, "(risk_score IS NULL AND risk_level IS NULL AND risk_calculation_id IS NULL) OR (risk_score IS NOT NULL AND risk_level IS NOT NULL AND risk_level IN ('low','medium','high','critical') AND risk_calculation_id IS NOT NULL)")
    op.execute("""
CREATE FUNCTION public.aegis_apply_risk(calculation_id uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  calc public.risk_calculations%ROWTYPE;
  target_mode text; target_dataset uuid; target_run uuid;
  source_count integer; actual_count integer;
BEGIN
  SELECT * INTO calc FROM public.risk_calculations WHERE id=calculation_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'risk calculation missing' USING ERRCODE='23514'; END IF;
  IF calc.subject_type='alert' THEN
    SELECT mode,dataset_id,run_id INTO target_mode,target_dataset,target_run FROM public.alerts WHERE id=calc.subject_id FOR UPDATE;
  ELSE
    SELECT mode,dataset_id,run_id INTO target_mode,target_dataset,target_run FROM public.incidents WHERE id=calc.subject_id FOR UPDATE;
  END IF;
  IF NOT FOUND OR target_mode IS DISTINCT FROM calc.mode OR target_run IS DISTINCT FROM calc.run_id OR target_dataset IS DISTINCT FROM calc.dataset_id THEN
    RAISE EXCEPTION 'risk subject scope mismatch' USING ERRCODE='23514';
  END IF;
  IF calc.subject_revision <> (SELECT max(subject_revision) FROM public.risk_calculations WHERE subject_type=calc.subject_type AND subject_id=calc.subject_id)
    OR calc.score IS DISTINCT FROM (calc.explanation->>'score')::integer
    OR calc.level IS DISTINCT FROM calc.explanation->>'level'
    OR jsonb_typeof(calc.input_snapshot->'source_alerts') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'risk head mismatch' USING ERRCODE='23514';
  END IF;
  source_count := jsonb_array_length(calc.input_snapshot->'source_alerts');
  IF EXISTS (
    SELECT 1 FROM jsonb_array_elements(calc.input_snapshot->'source_alerts') item
    LEFT JOIN public.alerts a ON a.id=(item->>'id')::uuid
    WHERE a.id IS NULL OR a.event_sha256 IS DISTINCT FROM item->>'event_sha256'
      OR a.rule_id IS DISTINCT FROM item->>'rule_id' OR a.rule_version IS DISTINCT FROM item->>'rule_version'
      OR a.evaluator_version IS DISTINCT FROM item->>'evaluator_version'
      OR a.severity IS DISTINCT FROM item->>'severity'
      OR a.mode IS DISTINCT FROM calc.mode OR a.run_id IS DISTINCT FROM calc.run_id
      OR (calc.mode='replay' AND a.dataset_id IS DISTINCT FROM calc.dataset_id)
      OR (calc.subject_type='alert' AND a.id<>calc.subject_id)
      OR (calc.subject_type='incident' AND ((a.status='false_positive') IS DISTINCT FROM (item->>'excluded')::boolean OR NOT EXISTS (
        SELECT 1 FROM public.incident_alerts link WHERE link.incident_id=calc.subject_id AND link.alert_id=a.id AND link.active)))
  ) THEN RAISE EXCEPTION 'risk proof mismatch' USING ERRCODE='23514'; END IF;
  IF (SELECT count(DISTINCT item->>'id') FROM jsonb_array_elements(calc.input_snapshot->'source_alerts') item) <> source_count THEN
    RAISE EXCEPTION 'risk duplicate proof' USING ERRCODE='23514';
  END IF;
  IF calc.subject_type='alert' THEN
    IF source_count<>1 THEN RAISE EXCEPTION 'risk alert proof missing' USING ERRCODE='23514'; END IF;
    UPDATE public.alerts SET risk_score=calc.score,risk_level=calc.level,risk_calculation_id=calc.id WHERE id=calc.subject_id;
  ELSE
    SELECT count(*) INTO actual_count FROM public.incident_alerts WHERE incident_id=calc.subject_id AND active;
    IF source_count<>actual_count THEN RAISE EXCEPTION 'risk incident proof missing' USING ERRCODE='23514'; END IF;
    UPDATE public.incidents SET risk_score=calc.score,risk_level=calc.level,risk_calculation_id=calc.id WHERE id=calc.subject_id;
  END IF;
END $$
""")
    op.execute("REVOKE ALL ON FUNCTION public.aegis_apply_risk(uuid) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION public.aegis_apply_risk(uuid) TO aegis_app")


def downgrade() -> None:
    op.execute("DO $$ BEGIN IF EXISTS (SELECT 1 FROM public.risk_calculations) THEN RAISE EXCEPTION 'risk history exists; downgrade would destroy immutable assessments' USING ERRCODE='23514'; END IF; END $$")
    op.execute("DROP FUNCTION public.aegis_apply_risk(uuid)")
    for table in ("incidents", "alerts"):
        op.drop_constraint(op.f(f"ck_{table}_consistent_risk_projection"), table, type_="check")
        op.drop_column(table, "risk_calculation_id")
        op.drop_column(table, "risk_level")
    op.drop_table("risk_calculations")
