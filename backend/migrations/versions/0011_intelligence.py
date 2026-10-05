"""Versioned local indicators and append-only frozen event matching evidence."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_intelligence"
down_revision: str | None = "0010_entities"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("ioc_identities", "ioc_revisions", "int_event_receipts", "int_event_matches")


def created(name: str = "created_at") -> sa.Column[sa.DateTime]:
    return sa.Column(
        name, sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
    )


def upgrade() -> None:
    op.create_table(
        "ioc_identities",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("canonical_value", sa.String(2048), nullable=False),
        sa.Column("normalization_version", sa.String(32), nullable=False),
        sa.Column("current_revision_id", sa.Uuid()),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("0")),
        created(),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.UniqueConstraint("kind", "canonical_value"),
        sa.CheckConstraint("kind IN ('ip','domain','url','hash')", name="valid_kind"),
        sa.CheckConstraint("char_length(canonical_value) BETWEEN 1 AND 2048", name="bounded_value"),
        sa.CheckConstraint(
            "(version=0 AND current_revision_id IS NULL) OR "
            "(version BETWEEN 1 AND 50 AND current_revision_id IS NOT NULL)",
            name="valid_pointer",
        ),
    )
    op.create_index("ix_ioc_identities_created", "ioc_identities", ["created_at", "id"])
    op.create_table(
        "ioc_revisions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("ioc_id", sa.Uuid(), sa.ForeignKey("ioc_identities.id"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("canonical_document", sa.Text(), nullable=False),
        sa.Column("document_sha256", sa.String(64), nullable=False),
        created(),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.UniqueConstraint("ioc_id", "revision"),
        sa.CheckConstraint("revision BETWEEN 1 AND 50", name="bounded_revision"),
        sa.CheckConstraint("document_sha256 ~ '^[0-9a-f]{64}$'", name="valid_document_hash"),
        sa.CheckConstraint(
            "jsonb_typeof(document)='object' AND octet_length(document::text)<=32768",
            name="bounded_document",
        ),
        sa.CheckConstraint(
            "octet_length(canonical_document) BETWEEN 1 AND 32768", name="bounded_canonical"
        ),
    )
    op.create_foreign_key(
        "fk_ioc_current_revision",
        "ioc_identities",
        "ioc_revisions",
        ["current_revision_id"],
        ["id"],
    )
    op.create_table(
        "int_event_receipts",
        sa.Column(
            "event_id", sa.Uuid(), sa.ForeignKey("normalized_events.event_id"), primary_key=True
        ),
        sa.Column("document_sha256", sa.String(64), nullable=False),
        sa.Column("normalization_version", sa.String(32), nullable=False),
        sa.Column("mode", sa.String(8), nullable=False),
        sa.Column("dataset_id", sa.Uuid()),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("match_count", sa.Integer(), nullable=False),
        created("evaluated_at"),
        sa.CheckConstraint("document_sha256 ~ '^[0-9a-f]{64}$'", name="valid_document_hash"),
        sa.CheckConstraint("match_count BETWEEN 0 AND 32", name="bounded_matches"),
        sa.CheckConstraint(
            "(mode='live' AND dataset_id IS NULL AND "
            "run_id='00000000-0000-0000-0000-000000000000'::uuid) OR "
            "(mode='replay' AND dataset_id IS NOT NULL AND "
            "dataset_id<>'00000000-0000-0000-0000-000000000000'::uuid AND "
            "run_id<>'00000000-0000-0000-0000-000000000000'::uuid)",
            name="valid_scope",
        ),
    )
    op.create_table(
        "int_event_matches",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "event_id", sa.Uuid(), sa.ForeignKey("int_event_receipts.event_id"), nullable=False
        ),
        sa.Column("ioc_id", sa.Uuid(), sa.ForeignKey("ioc_identities.id"), nullable=False),
        sa.Column("revision_id", sa.Uuid(), sa.ForeignKey("ioc_revisions.id"), nullable=False),
        sa.Column("field", sa.String(128), nullable=False),
        sa.Column("observed_value", sa.String(8192), nullable=False),
        sa.Column("canonical_value", sa.String(2048), nullable=False),
        sa.Column("revision_snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("revision_snapshot_sha256", sa.String(64), nullable=False),
        sa.UniqueConstraint("event_id", "revision_id", "field"),
        sa.CheckConstraint("char_length(field) BETWEEN 1 AND 128", name="bounded_field"),
        sa.CheckConstraint(
            "char_length(observed_value) BETWEEN 1 AND 8192 AND "
            "char_length(canonical_value) BETWEEN 1 AND 2048",
            name="bounded_value",
        ),
        sa.CheckConstraint(
            "revision_snapshot_sha256 ~ '^[0-9a-f]{64}$'", name="valid_snapshot_hash"
        ),
        sa.CheckConstraint(
            "jsonb_typeof(revision_snapshot)='object' AND "
            "octet_length(revision_snapshot::text)<=32768",
            name="bounded_snapshot",
        ),
    )
    op.create_index("ix_int_event_matches_ioc_event", "int_event_matches", ["ioc_id", "event_id"])
    op.execute("GRANT SELECT, INSERT ON " + ",".join(TABLES) + " TO aegis_app")
    op.execute("""
CREATE FUNCTION public.aegis_intelligence_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog, public AS $$
BEGIN
 IF TG_TABLE_NAME='ioc_identities' AND TG_OP='UPDATE' THEN
  IF (NEW.id,NEW.kind,NEW.canonical_value,NEW.normalization_version,NEW.created_at,NEW.created_by)
   IS DISTINCT FROM (OLD.id,OLD.kind,OLD.canonical_value,OLD.normalization_version,
                     OLD.created_at,OLD.created_by)
   OR NEW.version<>OLD.version+1 THEN
   RAISE EXCEPTION 'IOC identity is immutable' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 RAISE EXCEPTION 'Intelligence evidence is append only' USING ERRCODE='23514';
END $$
""")
    for table in TABLES:
        op.execute(
            f"CREATE TRIGGER intelligence_immutable BEFORE UPDATE OR DELETE ON public.{table} "
            "FOR EACH ROW EXECUTE FUNCTION public.aegis_intelligence_immutable()"
        )
        op.execute(
            f"CREATE TRIGGER intelligence_no_truncate BEFORE TRUNCATE ON public.{table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION public.aegis_intelligence_immutable()"
        )
    op.execute("""
CREATE FUNCTION public.aegis_intelligence_validate() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog, public AS $$
BEGIN
 IF TG_TABLE_NAME='ioc_identities' THEN
  IF NEW.version<>0 OR NEW.current_revision_id IS NOT NULL
    OR NEW.normalization_version<>'ioc-normalization-v1' THEN
    RAISE EXCEPTION 'IOC identity must start unpublished' USING ERRCODE='23514'; END IF;
 ELSIF TG_TABLE_NAME='ioc_revisions' THEN
  IF NEW.document<>NEW.canonical_document::jsonb OR
    NEW.document_sha256<>encode(sha256(convert_to(NEW.canonical_document,'UTF8')),'hex') OR
    NEW.document->>'ioc_id' IS DISTINCT FROM NEW.ioc_id::text OR
    NEW.document->>'revision_id' IS DISTINCT FROM NEW.id::text OR
    (NEW.document->>'revision')::integer IS DISTINCT FROM NEW.revision OR
    NEW.document->>'normalization_version' IS DISTINCT FROM 'ioc-normalization-v1' OR
    NOT EXISTS (SELECT 1 FROM public.ioc_identities i WHERE i.id=NEW.ioc_id
      AND i.kind=NEW.document->>'type' AND i.canonical_value=NEW.document->>'value'
      AND i.canonical_value=NEW.document->>'canonical_value') THEN
    RAISE EXCEPTION 'IOC revision source mismatch' USING ERRCODE='23514'; END IF;
 ELSIF TG_TABLE_NAME='int_event_receipts' THEN
  IF NEW.normalization_version<>'ioc-normalization-v1' OR NOT EXISTS (
    SELECT 1 FROM public.normalized_events n JOIN public.raw_events r ON r.id=n.event_id
    WHERE n.event_id=NEW.event_id AND n.document_sha256=NEW.document_sha256
      AND r.mode=NEW.mode AND r.run_id=NEW.run_id
      AND (NEW.mode='live' OR r.dataset_id=NEW.dataset_id)) THEN
    RAISE EXCEPTION 'Intelligence receipt source mismatch' USING ERRCODE='23514'; END IF;
 ELSE
  IF NOT EXISTS (SELECT 1 FROM public.ioc_revisions v
    JOIN public.ioc_identities i ON i.id=v.ioc_id
    JOIN public.int_event_receipts p ON p.event_id=NEW.event_id
    WHERE v.id=NEW.revision_id AND v.ioc_id=NEW.ioc_id
      AND v.document=NEW.revision_snapshot AND v.document_sha256=NEW.revision_snapshot_sha256
      AND v.document->>'active'='true' AND i.canonical_value=NEW.canonical_value
      AND v.created_at<=p.evaluated_at) THEN
    RAISE EXCEPTION 'Intelligence match revision mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$
""")
    for table in TABLES:
        op.execute(
            f"CREATE TRIGGER intelligence_validate BEFORE INSERT ON public.{table} "
            "FOR EACH ROW EXECUTE FUNCTION public.aegis_intelligence_validate()"
        )
    op.execute("""
CREATE FUNCTION public.aegis_intelligence_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog, public AS $$
DECLARE expected integer; actual integer;
BEGIN
 IF TG_TABLE_NAME='ioc_identities' THEN
  IF NOT EXISTS (SELECT 1 FROM public.ioc_identities i
    JOIN public.ioc_revisions r ON r.id=i.current_revision_id AND r.ioc_id=i.id
    WHERE i.id=NEW.id AND r.revision=i.version AND i.version>0) THEN
    RAISE EXCEPTION 'IOC pointer is incomplete' USING ERRCODE='23514'; END IF;
 ELSE
  SELECT match_count INTO expected FROM public.int_event_receipts WHERE event_id=NEW.event_id;
  SELECT count(*) INTO actual FROM public.int_event_matches WHERE event_id=NEW.event_id;
  IF expected IS NULL OR expected<>actual THEN
    RAISE EXCEPTION 'Intelligence receipt is incomplete' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$
""")
    op.execute(
        "CREATE CONSTRAINT TRIGGER intelligence_complete AFTER INSERT OR UPDATE ON "
        "public.ioc_identities DEFERRABLE INITIALLY DEFERRED "
        "FOR EACH ROW EXECUTE FUNCTION public.aegis_intelligence_complete()"
    )
    for table in TABLES[2:]:
        op.execute(
            f"CREATE CONSTRAINT TRIGGER intelligence_complete AFTER INSERT ON public.{table} "
            "DEFERRABLE INITIALLY DEFERRED "
            "FOR EACH ROW EXECUTE FUNCTION public.aegis_intelligence_complete()"
        )
    op.execute("""
CREATE FUNCTION public.aegis_select_ioc_revision(ioc uuid, selected uuid, actor uuid)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog, public AS $$
DECLARE previous integer; target integer;
BEGIN
 PERFORM pg_advisory_xact_lock(280334879059);
 IF NOT EXISTS (SELECT 1 FROM public.users u WHERE u.id=actor AND u.enabled
   AND u.role::text IN ('admin','soc_manager')) THEN
   RAISE EXCEPTION 'IOC publication actor unavailable' USING ERRCODE='23514'; END IF;
 SELECT i.version INTO previous FROM public.ioc_identities i WHERE i.id=ioc FOR UPDATE;
 SELECT v.revision INTO target FROM public.ioc_revisions v WHERE v.id=selected AND v.ioc_id=ioc
   AND v.created_by=actor
   AND v.document_sha256=encode(sha256(convert_to(v.canonical_document,'UTF8')),'hex')
   AND v.document=v.canonical_document::jsonb;
 IF previous IS NULL OR target IS NULL OR target<>previous+1 OR target>50 THEN
   RAISE EXCEPTION 'IOC revision must advance once' USING ERRCODE='23514'; END IF;
 UPDATE public.ioc_identities SET current_revision_id=selected,version=target WHERE id=ioc;
 RETURN target;
END $$
""")
    for suffix in ("immutable", "validate", "complete"):
        op.execute(f"REVOKE ALL ON FUNCTION public.aegis_intelligence_{suffix}() FROM PUBLIC")
    op.execute(
        "REVOKE ALL ON FUNCTION public.aegis_select_ioc_revision(uuid,uuid,uuid) FROM PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION public.aegis_select_ioc_revision(uuid,uuid,uuid) TO aegis_app"
    )
    op.execute(
        "INSERT INTO public.rule_deployments(id,rule_version,enabled,version) "
        "VALUES('ti:malicious-indicator','1.0.0',true,1)"
    )


def downgrade() -> None:
    condition = " OR ".join(f"EXISTS (SELECT 1 FROM public.{table})" for table in TABLES)
    op.execute(
        f"DO $$ BEGIN IF {condition} OR EXISTS (SELECT 1 FROM public.alerts "
        "WHERE rule_id='ti:malicious-indicator') THEN RAISE EXCEPTION "
        "'Intelligence history exists; downgrade would destroy immutable evidence' "
        "USING ERRCODE='23514'; END IF; END $$"
    )
    op.execute("DELETE FROM public.rule_deployments WHERE id='ti:malicious-indicator'")
    op.execute("DROP FUNCTION public.aegis_select_ioc_revision(uuid,uuid,uuid)")
    op.drop_constraint("fk_ioc_current_revision", "ioc_identities", type_="foreignkey")
    for table in reversed(TABLES):
        op.drop_table(table)
    for suffix in ("immutable", "validate", "complete"):
        op.execute(f"DROP FUNCTION public.aegis_intelligence_{suffix}()")
