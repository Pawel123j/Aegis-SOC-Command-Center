"""Append-only Sigma definitions and narrowly selected disabled deployments."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_sigma"
down_revision: str | None = "0008_mitre"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sigma_rules",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("detection_id", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.CheckConstraint("detection_id = 'sigma:' || id::text", name="identity_deployment"),
    )
    op.create_table(
        "sigma_rule_versions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("rule_id", sa.Uuid(), sa.ForeignKey("sigma_rules.id"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("definition_yaml", sa.Text(), nullable=False),
        sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("compiled_sha256", sa.String(64), nullable=False),
        sa.Column("evaluator_version", sa.String(32), nullable=False),
        sa.Column("compiled", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.UniqueConstraint("rule_id", "revision"),
        sa.CheckConstraint("revision BETWEEN 1 AND 20", name="bounded_revision"),
        sa.CheckConstraint(
            "octet_length(definition_yaml) BETWEEN 1 AND 65536", name="bounded_yaml"
        ),
        sa.CheckConstraint("source_sha256 ~ '^[0-9a-f]{64}$'", name="valid_source_hash"),
        sa.CheckConstraint("compiled_sha256 ~ '^[0-9a-f]{64}$'", name="valid_compiled_hash"),
        sa.CheckConstraint("jsonb_typeof(compiled)='object'", name="object_compiled"),
    )
    op.execute("GRANT SELECT, INSERT ON sigma_rules, sigma_rule_versions TO aegis_app")
    op.execute("""
CREATE FUNCTION public.aegis_select_sigma_revision(rule uuid, selected integer, actor uuid)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog, public AS $$
DECLARE identity text; previous integer; current_revision text;
BEGIN
  PERFORM pg_advisory_xact_lock(280334879059);
  IF NOT EXISTS (SELECT 1 FROM public.users u WHERE u.id=actor AND u.enabled
    AND u.role::text IN ('admin','soc_manager')) THEN
    RAISE EXCEPTION 'Sigma import actor unavailable' USING ERRCODE='23514';
  END IF;
  SELECT r.detection_id INTO identity FROM public.sigma_rules r
    JOIN public.sigma_rule_versions v ON v.rule_id=r.id
    WHERE r.id=rule AND v.revision=selected AND v.evaluator_version='sigma-subset-v1'
      AND v.compiled->>'evaluator_version'='sigma-subset-v1'
      AND v.compiled->>'schema_version'='1'
      AND v.source_sha256=encode(sha256(convert_to(v.definition_yaml,'UTF8')),'hex')
      AND v.compiled->'metadata'->>'sigma_id'=r.id::text;
  IF identity IS NULL OR identity <> 'sigma:' || rule::text THEN
    RAISE EXCEPTION 'Sigma revision unavailable' USING ERRCODE='23514';
  END IF;
  SELECT d.version,d.rule_version INTO previous,current_revision
    FROM public.rule_deployments d WHERE d.id=identity FOR UPDATE;
  IF previous IS NULL THEN
    IF selected<>1 THEN RAISE EXCEPTION 'First Sigma revision must be one' USING ERRCODE='23514'; END IF;
    INSERT INTO public.rule_deployments(id,rule_version,enabled,updated_by)
      VALUES(identity,selected::text,false,actor);
    RETURN 1;
  END IF;
  IF selected::text=current_revision OR selected<>current_revision::integer+1 THEN
    RAISE EXCEPTION 'Sigma revision must advance once' USING ERRCODE='23514';
  END IF;
  UPDATE public.rule_deployments SET rule_version=selected::text,enabled=false,
    version=version+1,updated_at=now(),updated_by=actor WHERE id=identity;
  RETURN previous+1;
END $$
""")
    op.execute(
        "REVOKE ALL ON FUNCTION public.aegis_select_sigma_revision(uuid,integer,uuid) FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION public.aegis_select_sigma_revision(uuid,integer,uuid) TO aegis_app"
    )


def downgrade() -> None:
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM public.sigma_rules) THEN RAISE EXCEPTION 'Sigma history exists; downgrade would destroy immutable definitions' USING ERRCODE='23514'; END IF; END $$"
    )
    op.execute("DROP FUNCTION public.aegis_select_sigma_revision(uuid,integer,uuid)")
    op.drop_table("sigma_rule_versions")
    op.drop_table("sigma_rules")
