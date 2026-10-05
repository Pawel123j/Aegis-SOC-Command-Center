"""Append-only evidence-derived identities and indexed original alert contributors."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_entities"
down_revision: str | None = "0009_sigma"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = (
    "entity_identities", "entity_index_receipts", "entity_observations",
    "entity_alert_receipts", "alert_event_references",
)


def _created() -> sa.Column[sa.DateTime]:
    return sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()"))


def upgrade() -> None:
    op.create_table(
        "entity_identities",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("key_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("label", sa.String(256), nullable=False),
        sa.Column("identity_policy", sa.String(32), nullable=False),
        sa.Column("identity_basis", sa.String(32), nullable=False),
        sa.Column("canonical_identity", postgresql.JSONB(), nullable=False),
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ingestion_sources.id")),
        sa.Column("mode", sa.String(8), nullable=False),
        sa.Column("dataset_id", sa.Uuid()),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        _created(),
        sa.CheckConstraint("kind IN ('host','user','ip','process')", name="valid_kind"),
        sa.CheckConstraint("key_sha256 ~ '^[0-9a-f]{64}$'", name="valid_key_hash"),
        sa.CheckConstraint("jsonb_typeof(canonical_identity)='object' AND octet_length(canonical_identity::text)<=8192", name="bounded_identity"),
        sa.CheckConstraint("char_length(label) BETWEEN 1 AND 256", name="bounded_label"),
        sa.CheckConstraint("(mode='live' AND dataset_id IS NULL AND run_id='00000000-0000-0000-0000-000000000000'::uuid) OR (mode='replay' AND dataset_id IS NOT NULL AND dataset_id<>'00000000-0000-0000-0000-000000000000'::uuid AND run_id<>'00000000-0000-0000-0000-000000000000'::uuid)", name="valid_scope"),
    )
    op.create_index("ix_entities_scope_kind_created", "entity_identities", ["mode", "dataset_id", "run_id", "kind", "created_at", "id"])
    op.create_table(
        "entity_index_receipts",
        sa.Column("event_id", sa.Uuid(), sa.ForeignKey("normalized_events.event_id"), primary_key=True),
        sa.Column("document_sha256", sa.String(64), nullable=False),
        sa.Column("identity_policy", sa.String(32), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        _created(),
        sa.CheckConstraint("document_sha256 ~ '^[0-9a-f]{64}$'", name="valid_document_hash"),
        sa.CheckConstraint("observation_count BETWEEN 0 AND 8", name="bounded_observations"),
    )
    op.create_table(
        "entity_observations",
        sa.Column("entity_id", sa.Uuid(), sa.ForeignKey("entity_identities.id"), primary_key=True),
        sa.Column("event_id", sa.Uuid(), sa.ForeignKey("entity_index_receipts.event_id"), primary_key=True),
        sa.Column("role", sa.String(32), primary_key=True),
        sa.Column("attributes", postgresql.JSONB(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("document_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint("document_sha256 ~ '^[0-9a-f]{64}$'", name="valid_document_hash"),
        sa.CheckConstraint("char_length(role) BETWEEN 1 AND 32", name="bounded_role"),
        sa.CheckConstraint("jsonb_typeof(attributes)='object' AND octet_length(attributes::text)<=8192", name="bounded_attributes"),
    )
    op.create_index("ix_entity_observations_entity_time", "entity_observations", ["entity_id", "timestamp", "event_id"])
    op.create_index("ix_entity_observations_event", "entity_observations", ["event_id", "entity_id"])
    op.create_table(
        "entity_alert_receipts",
        sa.Column("alert_id", sa.Uuid(), sa.ForeignKey("alerts.id"), primary_key=True),
        sa.Column("contributor_count", sa.Integer(), nullable=False),
        _created(),
        sa.CheckConstraint("contributor_count BETWEEN 1 AND 100", name="bounded_contributors"),
    )
    op.create_table(
        "alert_event_references",
        sa.Column("alert_id", sa.Uuid(), sa.ForeignKey("entity_alert_receipts.alert_id"), primary_key=True),
        sa.Column("event_id", sa.Uuid(), sa.ForeignKey("normalized_events.event_id"), primary_key=True),
        sa.Column("document_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint("document_sha256 ~ '^[0-9a-f]{64}$'", name="valid_document_hash"),
    )
    op.create_index("ix_alert_event_references_event_alert", "alert_event_references", ["event_id", "alert_id"])
    op.execute("GRANT SELECT, INSERT ON " + ",".join(TABLES) + " TO aegis_app")
    op.execute("""
CREATE FUNCTION public.aegis_entities_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog, public AS $$
BEGIN RAISE EXCEPTION 'Entity evidence is append only' USING ERRCODE='23514'; END $$
""")
    for table in TABLES:
        op.execute(f"CREATE TRIGGER entities_immutable BEFORE UPDATE OR DELETE ON public.{table} FOR EACH ROW EXECUTE FUNCTION public.aegis_entities_immutable()")
        op.execute(f"CREATE TRIGGER entities_no_truncate BEFORE TRUNCATE ON public.{table} FOR EACH STATEMENT EXECUTE FUNCTION public.aegis_entities_immutable()")
    op.execute("""
CREATE FUNCTION public.aegis_entities_validate() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog, public AS $$
BEGIN
 IF TG_TABLE_NAME='entity_index_receipts' THEN
   IF NOT EXISTS (SELECT 1 FROM public.normalized_events n WHERE n.event_id=NEW.event_id
       AND n.document_sha256=NEW.document_sha256) THEN
     RAISE EXCEPTION 'Entity receipt source mismatch' USING ERRCODE='23514'; END IF;
 ELSIF TG_TABLE_NAME='entity_observations' THEN
   IF NOT EXISTS (SELECT 1 FROM public.normalized_events n
       JOIN public.raw_events r ON r.id=n.event_id
       JOIN public.entity_index_receipts p ON p.event_id=n.event_id
       JOIN public.entity_identities i ON i.id=NEW.entity_id
       WHERE n.event_id=NEW.event_id AND n.timestamp=NEW.timestamp
         AND n.document_sha256=NEW.document_sha256 AND p.document_sha256=n.document_sha256
         AND p.identity_policy=i.identity_policy AND i.mode=r.mode AND i.run_id=r.run_id
         AND (i.mode='live' OR i.dataset_id=r.dataset_id)
         AND (i.source_id IS NULL OR i.source_id=r.source_id)) THEN
     RAISE EXCEPTION 'Entity observation source mismatch' USING ERRCODE='23514'; END IF;
 ELSIF TG_TABLE_NAME='entity_alert_receipts' THEN
   IF NOT EXISTS (SELECT 1 FROM public.alerts a WHERE a.id=NEW.alert_id AND
       NEW.contributor_count=CASE WHEN jsonb_array_length(a.event_snapshots)>0
          THEN jsonb_array_length(a.event_snapshots) ELSE 1 END) THEN
     RAISE EXCEPTION 'Entity alert receipt contributor mismatch' USING ERRCODE='23514'; END IF;
 ELSIF TG_TABLE_NAME='alert_event_references' THEN
   IF NOT EXISTS (SELECT 1 FROM public.alerts a
       JOIN public.normalized_events n ON n.event_id=NEW.event_id
       JOIN public.raw_events r ON r.id=n.event_id
       WHERE a.id=NEW.alert_id AND n.document_sha256=NEW.document_sha256
         AND a.mode=r.mode AND a.run_id=r.run_id AND (a.mode='live' OR a.dataset_id=r.dataset_id)
         AND ((jsonb_array_length(a.event_snapshots)=0 AND a.event_id=n.event_id
               AND a.event_sha256=n.document_sha256 AND a.event_snapshot=n.document)
            OR EXISTS (SELECT 1 FROM jsonb_array_elements(a.event_snapshots) p
               WHERE p->>'event_id'=n.event_id::text AND p->>'event_sha256'=n.document_sha256
                 AND p->'event_snapshot'=n.document))) THEN
     RAISE EXCEPTION 'Entity alert reference source mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$
""")
    for table in TABLES[1:]:
        op.execute(f"CREATE TRIGGER entities_validate BEFORE INSERT ON public.{table} FOR EACH ROW EXECUTE FUNCTION public.aegis_entities_validate()")
    op.execute("""
CREATE FUNCTION public.aegis_entities_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog, public AS $$
DECLARE expected integer; actual integer;
BEGIN
 IF TG_TABLE_NAME IN ('entity_index_receipts','entity_observations') THEN
   SELECT observation_count INTO expected FROM public.entity_index_receipts WHERE event_id=NEW.event_id;
   SELECT count(*) INTO actual FROM public.entity_observations WHERE event_id=NEW.event_id;
 ELSE
   SELECT contributor_count INTO expected FROM public.entity_alert_receipts WHERE alert_id=NEW.alert_id;
   SELECT count(*) INTO actual FROM public.alert_event_references WHERE alert_id=NEW.alert_id;
 END IF;
 IF expected IS NULL OR actual<>expected THEN
   RAISE EXCEPTION 'Entity receipt is incomplete' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$
""")
    for table in TABLES[1:]:
        op.execute(f"CREATE CONSTRAINT TRIGGER entities_complete AFTER INSERT ON public.{table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.aegis_entities_complete()")
    for name in ("immutable", "validate", "complete"):
        op.execute(f"REVOKE ALL ON FUNCTION public.aegis_entities_{name}() FROM PUBLIC")


def downgrade() -> None:
    condition = " OR ".join(f"EXISTS (SELECT 1 FROM public.{table})" for table in TABLES)
    op.execute(f"DO $$ BEGIN IF {condition} THEN RAISE EXCEPTION 'Entity history exists; downgrade would destroy immutable evidence' USING ERRCODE='23514'; END IF; END $$")
    for table in reversed(TABLES):
        op.drop_table(table)
    for name in ("immutable", "validate", "complete"):
        op.execute(f"DROP FUNCTION public.aegis_entities_{name}()")
