"""Durable simulation-only workflows and append-only local action history."""

from alembic import op

revision = "0012_soar"
down_revision = "0011_intelligence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE playbooks (
    id UUID NOT NULL,
    latest_revision INTEGER NOT NULL,
    published_revision INTEGER,
    enabled BOOLEAN NOT NULL,
    version INTEGER NOT NULL,
    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_playbooks PRIMARY KEY (id),
    CONSTRAINT ck_playbooks_bounded_revision CHECK (latest_revision BETWEEN 1 AND 20),
    CONSTRAINT ck_playbooks_published_revision CHECK (published_revision IS NULL OR
        published_revision BETWEEN 1 AND latest_revision),
    CONSTRAINT ck_playbooks_positive_version CHECK (version >= 1),
    CONSTRAINT fk_playbooks_created_by_users FOREIGN KEY(created_by) REFERENCES users (id)
)
""")
    op.execute("""
CREATE TABLE playbook_revisions (
    id UUID NOT NULL,
    playbook_id UUID NOT NULL,
    revision INTEGER NOT NULL,
    engine_version VARCHAR(32) NOT NULL,
    document JSONB NOT NULL,
    canonical_document TEXT NOT NULL,
    document_sha256 VARCHAR(64) NOT NULL,
    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_playbook_revisions PRIMARY KEY (id),
    CONSTRAINT uq_playbook_revisions_playbook_id UNIQUE (playbook_id, revision),
    CONSTRAINT ck_playbook_revisions_bounded_revision CHECK (revision BETWEEN 1 AND 20),
    CONSTRAINT ck_playbook_revisions_valid_hash CHECK (document_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_playbook_revisions_bounded_document CHECK (octet_length(canonical_document)
        BETWEEN 1 AND 16384),
    CONSTRAINT fk_playbook_revisions_playbook_id_playbooks FOREIGN KEY(playbook_id) REFERENCES
        playbooks (id),
    CONSTRAINT fk_playbook_revisions_created_by_users FOREIGN KEY(created_by) REFERENCES users
        (id)
)
""")
    op.execute("""
CREATE TABLE playbook_runs (
    id UUID NOT NULL,
    revision_id UUID NOT NULL,
    alert_id UUID NOT NULL,
    requested_by UUID NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    request_sha256 VARCHAR(64) NOT NULL,
    replay_of UUID,
    execution_mode VARCHAR(16) NOT NULL,
    mode VARCHAR(8) NOT NULL,
    dataset_id UUID NOT NULL,
    data_run_id UUID NOT NULL,
    context JSONB NOT NULL,
    context_sha256 VARCHAR(64) NOT NULL,
    state VARCHAR(16) NOT NULL,
    cancellation_requested BOOLEAN NOT NULL,
    error_code VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE,
    finished_at TIMESTAMP WITH TIME ZONE,
    next_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL,
    deadline_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_playbook_runs PRIMARY KEY (id),
    CONSTRAINT uq_playbook_runs_requested_by UNIQUE (requested_by, idempotency_key),
    CONSTRAINT ck_playbook_runs_valid_state CHECK (state IN
        ('queued','running','completed','failed','cancelled')),
    CONSTRAINT ck_playbook_runs_simulation_only CHECK (execution_mode='simulation'),
    CONSTRAINT ck_playbook_runs_valid_scope CHECK ((mode='live' AND
        data_run_id='00000000-0000-0000-0000-000000000000'::uuid) OR (mode='replay' AND
        data_run_id<>'00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT ck_playbook_runs_bounded_context CHECK (octet_length(context::text) <= 131072),
    CONSTRAINT ck_playbook_runs_valid_hashes CHECK (context_sha256 ~ '^[0-9a-f]{64}$' AND
        request_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT fk_playbook_runs_revision_id_playbook_revisions FOREIGN KEY(revision_id)
        REFERENCES playbook_revisions (id),
    CONSTRAINT fk_playbook_runs_alert_id_alerts FOREIGN KEY(alert_id) REFERENCES alerts (id),
    CONSTRAINT fk_playbook_runs_requested_by_users FOREIGN KEY(requested_by) REFERENCES users
        (id),
    CONSTRAINT fk_playbook_runs_replay_of_playbook_runs FOREIGN KEY(replay_of) REFERENCES
        playbook_runs (id)
)
""")
    op.execute("CREATE INDEX ix_playbook_runs_alert_id ON playbook_runs (alert_id)")
    op.execute("CREATE INDEX ix_playbook_runs_ready ON playbook_runs (state, next_attempt_at)")
    op.execute(
        "CREATE INDEX ix_playbook_runs_scope ON playbook_runs (mode, dataset_id, "
        "data_run_id, created_at, id)"
    )
    op.execute("""
CREATE TABLE playbook_steps (
    id UUID NOT NULL,
    run_id UUID NOT NULL,
    position INTEGER NOT NULL,
    step_id VARCHAR(32) NOT NULL,
    action VARCHAR(48) NOT NULL,
    input_sha256 VARCHAR(64) NOT NULL,
    state VARCHAR(16) NOT NULL,
    attempts INTEGER NOT NULL,
    lease_until TIMESTAMP WITH TIME ZONE,
    started_at TIMESTAMP WITH TIME ZONE,
    finished_at TIMESTAMP WITH TIME ZONE,
    error_code VARCHAR(64),
    CONSTRAINT pk_playbook_steps PRIMARY KEY (id),
    CONSTRAINT uq_playbook_steps_run_position UNIQUE (run_id, position),
    CONSTRAINT uq_playbook_steps_run_key UNIQUE (run_id, step_id),
    CONSTRAINT ck_playbook_steps_bounded_position CHECK (position BETWEEN 0 AND 19),
    CONSTRAINT ck_playbook_steps_bounded_attempts CHECK (attempts BETWEEN 0 AND 3),
    CONSTRAINT ck_playbook_steps_valid_state CHECK (state IN
        ('waiting','running','completed','failed')),
    CONSTRAINT fk_playbook_steps_run_id_playbook_runs FOREIGN KEY(run_id) REFERENCES
        playbook_runs (id)
)
""")
    op.execute("""
CREATE TABLE playbook_attempts (
    id UUID NOT NULL,
    step_id UUID NOT NULL,
    number INTEGER NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    finished_at TIMESTAMP WITH TIME ZONE NOT NULL,
    outcome VARCHAR(16) NOT NULL,
    error_code VARCHAR(64),
    CONSTRAINT pk_playbook_attempts PRIMARY KEY (id),
    CONSTRAINT uq_playbook_attempts_step_id UNIQUE (step_id, number),
    CONSTRAINT ck_playbook_attempts_bounded_number CHECK (number BETWEEN 1 AND 3),
    CONSTRAINT ck_playbook_attempts_valid_outcome CHECK (outcome IN
        ('completed','failed','expired','cancelled')),
    CONSTRAINT fk_playbook_attempts_step_id_playbook_steps FOREIGN KEY(step_id) REFERENCES
        playbook_steps (id)
)
""")
    op.execute("""
CREATE TABLE playbook_effects (
    step_id UUID NOT NULL,
    output JSONB NOT NULL,
    output_sha256 VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_playbook_effects PRIMARY KEY (step_id),
    CONSTRAINT ck_playbook_effects_bounded_output CHECK (octet_length(output::text) <= 65536),
    CONSTRAINT ck_playbook_effects_valid_hash CHECK (output_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT fk_playbook_effects_step_id_playbook_steps FOREIGN KEY(step_id) REFERENCES
        playbook_steps (id)
)
""")
    op.execute("""
CREATE TABLE soar_notifications (
    id UUID NOT NULL,
    step_id UUID NOT NULL,
    recipient_id UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    message VARCHAR(512) NOT NULL,
    read_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT pk_soar_notifications PRIMARY KEY (id),
    CONSTRAINT uq_soar_notifications_step_id UNIQUE (step_id),
    CONSTRAINT fk_soar_notifications_step_id_playbook_steps FOREIGN KEY(step_id) REFERENCES
        playbook_steps (id),
    CONSTRAINT fk_soar_notifications_recipient_id_users FOREIGN KEY(recipient_id) REFERENCES
        users (id)
)
""")
    op.execute(
        "CREATE INDEX ix_soar_notifications_recipient_id ON soar_notifications (recipient_id)"
    )
    op.execute(
        "GRANT SELECT, INSERT ON playbooks, playbook_revisions, playbook_runs, "
        "playbook_steps, playbook_attempts, playbook_effects, soar_notifications TO "
        "aegis_app"
    )
    op.execute(
        "GRANT UPDATE (latest_revision, published_revision, enabled, version) ON "
        "playbooks TO aegis_app"
    )
    op.execute(
        "GRANT UPDATE (state, cancellation_requested, error_code, started_at, "
        "finished_at, next_attempt_at) ON playbook_runs TO aegis_app"
    )
    op.execute(
        "GRANT UPDATE (state, attempts, lease_until, started_at, finished_at, "
        "error_code) ON playbook_steps TO aegis_app"
    )
    op.execute("GRANT UPDATE (read_at) ON soar_notifications TO aegis_app")
    op.execute("""
CREATE FUNCTION public.aegis_soar_terminal_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog, public AS $$
BEGIN
  IF OLD.state IN ('completed','failed','cancelled') AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'SOAR terminal history is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$
""")
    op.execute(
        "CREATE TRIGGER soar_run_terminal BEFORE UPDATE ON playbook_runs FOR EACH ROW "
        "EXECUTE FUNCTION public.aegis_soar_terminal_guard()"
    )
    op.execute(
        "CREATE TRIGGER soar_step_terminal BEFORE UPDATE ON playbook_steps FOR EACH ROW"
        " EXECUTE FUNCTION public.aegis_soar_terminal_guard()"
    )
    op.execute("""
CREATE FUNCTION public.aegis_soar_revision_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog, public AS $$
BEGIN
  IF NEW.document<>NEW.canonical_document::jsonb OR
     NEW.document_sha256<>encode(sha256(convert_to(NEW.canonical_document,'UTF8')),'hex')
     OR NEW.engine_version<>'local-soar-v1' THEN
    RAISE EXCEPTION 'SOAR revision proof mismatch' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$
""")
    op.execute(
        "CREATE TRIGGER soar_revision_proof BEFORE INSERT ON playbook_revisions FOR "
        "EACH ROW EXECUTE FUNCTION public.aegis_soar_revision_guard()"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.aegis_soar_terminal_guard(), "
        "public.aegis_soar_revision_guard() FROM PUBLIC"
    )


def downgrade() -> None:
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM playbooks) THEN RAISE EXCEPTION 'SOAR "
        "history exists; downgrade refused' USING ERRCODE='23514'; END IF; END $$"
    )
    op.drop_table("soar_notifications")
    op.drop_table("playbook_effects")
    op.drop_table("playbook_attempts")
    op.drop_table("playbook_steps")
    op.drop_table("playbook_runs")
    op.drop_table("playbook_revisions")
    op.drop_table("playbooks")
    op.execute(
        "DROP FUNCTION public.aegis_soar_terminal_guard(), public.aegis_soar_revision_guard()"
    )
