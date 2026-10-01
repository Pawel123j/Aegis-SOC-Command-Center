"""Scoped cases, immutable alert references and append-only analyst history.

Live cases span sources within one SOC organization. Replay cases isolate one
exact dataset/run. Automatic cases are created only for new High/Critical alerts.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005_incidents"
down_revision: str | None = "0004_initial_alerts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE incidents (
    id UUID NOT NULL,
    automatic_alert_id UUID,
    title VARCHAR(256) NOT NULL,
    description TEXT DEFAULT '' NOT NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(24) DEFAULT 'new' NOT NULL,
    risk_score INTEGER,
    confidence INTEGER,
    mode VARCHAR(8) NOT NULL,
    dataset_id UUID,
    run_id UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    created_by UUID,
    updated_by UUID,
    owner_id UUID,
    version INTEGER DEFAULT '1' NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    alert_count INTEGER DEFAULT '0' NOT NULL,
    tags JSONB DEFAULT '[]'::jsonb NOT NULL,
    dataset_ids JSONB DEFAULT '[]'::jsonb NOT NULL,
    related_users JSONB DEFAULT '[]'::jsonb NOT NULL,
    related_hosts JSONB DEFAULT '[]'::jsonb NOT NULL,
    related_ip_addresses JSONB DEFAULT '[]'::jsonb NOT NULL,
    mitre_techniques JSONB DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT pk_incidents PRIMARY KEY (id),
    CONSTRAINT ck_incidents_valid_status CHECK (status IN ('new','investigating','contained','resolved','closed')),
    CONSTRAINT ck_incidents_valid_severity CHECK (severity IN ('low','medium','high','critical')),
    CONSTRAINT ck_incidents_valid_scope CHECK ((mode = 'live' AND dataset_id IS NULL AND run_id = '00000000-0000-0000-0000-000000000000'::uuid) OR (mode = 'replay' AND dataset_id IS NOT NULL AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT ck_incidents_positive_version CHECK (version >= 1),
    CONSTRAINT ck_incidents_bounded_risk CHECK (risk_score IS NULL OR risk_score BETWEEN 0 AND 100),
    CONSTRAINT ck_incidents_bounded_confidence CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 100),
    CONSTRAINT ck_incidents_bounded_alert_count CHECK (alert_count BETWEEN 0 AND 100),
    CONSTRAINT ck_incidents_consistent_event_range CHECK ((first_seen IS NULL AND last_seen IS NULL AND alert_count = 0) OR (first_seen IS NOT NULL AND last_seen IS NOT NULL AND last_seen >= first_seen AND alert_count > 0)),
    CONSTRAINT ck_incidents_array_tags CHECK (jsonb_typeof(tags) = 'array' AND jsonb_array_length(tags) <= 20),
    CONSTRAINT ck_incidents_array_entities CHECK (jsonb_typeof(related_users) = 'array' AND jsonb_typeof(related_hosts) = 'array' AND jsonb_typeof(related_ip_addresses) = 'array' AND jsonb_typeof(mitre_techniques) = 'array' AND jsonb_typeof(dataset_ids) = 'array'),
    CONSTRAINT uq_incidents_automatic_alert_id UNIQUE (automatic_alert_id),
    CONSTRAINT fk_incidents_automatic_alert_id_alerts FOREIGN KEY(automatic_alert_id) REFERENCES alerts (id),
    CONSTRAINT fk_incidents_created_by_users FOREIGN KEY(created_by) REFERENCES users (id),
    CONSTRAINT fk_incidents_updated_by_users FOREIGN KEY(updated_by) REFERENCES users (id),
    CONSTRAINT fk_incidents_owner_id_users FOREIGN KEY(owner_id) REFERENCES users (id)
)
""")
    op.execute("CREATE INDEX ix_incidents_created_at_id ON incidents (created_at, id)")
    op.execute("CREATE INDEX ix_incidents_dataset_id ON incidents (dataset_id)")
    op.execute("CREATE INDEX ix_incidents_owner_id ON incidents (owner_id)")
    op.execute("CREATE INDEX ix_incidents_run_id ON incidents (run_id)")
    op.execute("CREATE INDEX ix_incidents_status ON incidents (status)")
    op.execute("""
CREATE TABLE incident_alerts (
    id UUID NOT NULL,
    incident_id UUID NOT NULL,
    alert_id UUID NOT NULL,
    linked_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    linked_by UUID,
    active BOOLEAN DEFAULT true NOT NULL,
    detached_at TIMESTAMP WITH TIME ZONE,
    detached_by UUID,
    CONSTRAINT pk_incident_alerts PRIMARY KEY (id),
    CONSTRAINT uq_incident_alerts_incident_alert UNIQUE (incident_id, alert_id),
    CONSTRAINT ck_incident_alerts_consistent_attachment CHECK ((active AND detached_at IS NULL) OR (NOT active AND detached_at IS NOT NULL)),
    CONSTRAINT fk_incident_alerts_incident_id_incidents FOREIGN KEY(incident_id) REFERENCES incidents (id),
    CONSTRAINT fk_incident_alerts_alert_id_alerts FOREIGN KEY(alert_id) REFERENCES alerts (id),
    CONSTRAINT fk_incident_alerts_linked_by_users FOREIGN KEY(linked_by) REFERENCES users (id),
    CONSTRAINT fk_incident_alerts_detached_by_users FOREIGN KEY(detached_by) REFERENCES users (id)
)
""")
    op.execute("CREATE INDEX ix_incident_alerts_alert_id ON incident_alerts (alert_id)")
    op.execute("CREATE INDEX ix_incident_alerts_incident_id ON incident_alerts (incident_id)")
    op.execute(
        "CREATE INDEX ix_incident_alerts_incident_linked ON incident_alerts (incident_id, linked_at, id)"
    )
    op.execute("""
CREATE TABLE incident_timeline (
    id UUID NOT NULL,
    incident_id UUID NOT NULL,
    kind VARCHAR(32) NOT NULL,
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    actor_id UUID,
    actor JSONB,
    data JSONB NOT NULL,
    CONSTRAINT pk_incident_timeline PRIMARY KEY (id),
    CONSTRAINT ck_incident_timeline_object_data CHECK (jsonb_typeof(data) = 'object'),
    CONSTRAINT fk_incident_timeline_incident_id_incidents FOREIGN KEY(incident_id) REFERENCES incidents (id),
    CONSTRAINT fk_incident_timeline_actor_id_users FOREIGN KEY(actor_id) REFERENCES users (id)
)
""")
    op.execute(
        "CREATE INDEX ix_incident_timeline_incident_time ON incident_timeline (incident_id, occurred_at, id)"
    )
    op.execute("""
CREATE TABLE incident_notes (
    id UUID NOT NULL,
    incident_id UUID NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    author_id UUID NOT NULL,
    author JSONB NOT NULL,
    CONSTRAINT pk_incident_notes PRIMARY KEY (id),
    CONSTRAINT ck_incident_notes_bounded_body CHECK (char_length(body) BETWEEN 1 AND 5000),
    CONSTRAINT fk_incident_notes_incident_id_incidents FOREIGN KEY(incident_id) REFERENCES incidents (id),
    CONSTRAINT fk_incident_notes_author_id_users FOREIGN KEY(author_id) REFERENCES users (id)
)
""")
    op.execute(
        "CREATE INDEX ix_incident_notes_incident_time ON incident_notes (incident_id, created_at, id)"
    )
    op.execute("""
CREATE TABLE incident_create_receipts (
    actor_id UUID NOT NULL,
    key VARCHAR(128) NOT NULL,
    body_sha256 VARCHAR(64) NOT NULL,
    incident_id UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_incident_create_receipts PRIMARY KEY (actor_id, key),
    CONSTRAINT fk_incident_create_receipts_actor_id_users FOREIGN KEY(actor_id) REFERENCES users (id),
    CONSTRAINT fk_incident_create_receipts_incident_id_incidents FOREIGN KEY(incident_id) REFERENCES incidents (id)
)
""")
    op.execute("GRANT SELECT, INSERT ON incidents TO aegis_app")
    op.execute(
        "GRANT UPDATE (title,description,severity,status,owner_id,tags,updated_at,updated_by,version,"
        "first_seen,last_seen,alert_count,dataset_ids,related_users,related_hosts,related_ip_addresses,"
        "mitre_techniques) ON incidents TO aegis_app"
    )
    op.execute("GRANT SELECT, INSERT ON incident_alerts TO aegis_app")
    op.execute("GRANT UPDATE (active,detached_at,detached_by) ON incident_alerts TO aegis_app")
    op.execute(
        "GRANT SELECT, INSERT ON incident_notes,incident_timeline,incident_create_receipts TO aegis_app"
    )
    # Runtime cannot edit scope, scores, original evidence references, notes, history or receipts.
    # The trigger is invoker-owned: only ordinary runtime reads/row locks are needed.
    op.execute("""
CREATE FUNCTION aegis_incident_alert_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    case_mode varchar(8);
    case_dataset uuid;
    case_run uuid;
    alert_mode varchar(8);
    alert_dataset uuid;
    alert_run uuid;
    active_total integer;
BEGIN
    SELECT mode,dataset_id,run_id INTO case_mode,case_dataset,case_run
    FROM incidents WHERE id=NEW.incident_id FOR UPDATE;
    SELECT mode,dataset_id,run_id INTO alert_mode,alert_dataset,alert_run
    FROM alerts WHERE id=NEW.alert_id;
    IF alert_mode IS DISTINCT FROM case_mode OR alert_run IS DISTINCT FROM case_run
       OR (case_mode='replay' AND alert_dataset IS DISTINCT FROM case_dataset) THEN
        RAISE EXCEPTION 'incident_scope_mismatch' USING ERRCODE='23514';
    END IF;
    IF NEW.active THEN
        SELECT count(*) INTO active_total FROM incident_alerts
        WHERE incident_id=NEW.incident_id AND active AND id<>NEW.id;
        IF active_total >= 100 THEN
            RAISE EXCEPTION 'incident_alert_limit' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$
""")
    op.execute("REVOKE ALL ON FUNCTION aegis_incident_alert_scope() FROM PUBLIC")
    op.execute("""
CREATE TRIGGER incident_alert_scope BEFORE INSERT OR UPDATE OF active ON incident_alerts
FOR EACH ROW EXECUTE FUNCTION aegis_incident_alert_scope()
""")


def downgrade() -> None:
    op.execute("DROP TRIGGER incident_alert_scope ON incident_alerts")
    op.execute("DROP FUNCTION aegis_incident_alert_scope()")
    op.drop_table("incident_create_receipts")
    op.drop_table("incident_notes")
    op.drop_table("incident_timeline")
    op.drop_table("incident_alerts")
    op.drop_table("incidents")
