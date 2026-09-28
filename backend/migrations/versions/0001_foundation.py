"""Users, persistent authentication sessions and append-only runtime audit.

Revision ID: 0001_foundation
Revises: None
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_foundation"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column(
            "role",
            sa.Enum(
                "admin",
                "soc_manager",
                "soc_analyst",
                "read_only",
                native_enum=False,
                create_constraint=True,
                name="user_role",
            ),
            nullable=False,
        ),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.CheckConstraint(
            "username ~ '^[a-z0-9][a-z0-9_.-]{2,63}$'", name=op.f("ck_users_username_normalized")
        ),
        sa.CheckConstraint("version >= 1", name=op.f("ck_users_positive_version")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("username", name=op.f("uq_users_username")),
    )
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("csrf_token_hash", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_auth_sessions_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_auth_sessions")),
    )
    op.create_index(op.f("ix_auth_sessions_user_id"), "auth_sessions", ["user_id"])
    op.create_index(
        op.f("ix_auth_sessions_absolute_expires_at"), "auth_sessions", ["absolute_expires_at"]
    )
    op.create_table(
        "refresh_tokens",
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["auth_sessions.id"],
            name=op.f("fk_refresh_tokens_session_id_auth_sessions"),
        ),
        sa.PrimaryKeyConstraint("token_hash", name=op.f("pk_refresh_tokens")),
    )
    op.create_index(op.f("ix_refresh_tokens_session_id"), "refresh_tokens", ["session_id"])
    op.create_index(op.f("ix_refresh_tokens_expires_at"), "refresh_tokens", ["expires_at"])
    op.create_table(
        "preauth_sessions",
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("csrf_token_hash", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("token_hash", name=op.f("pk_preauth_sessions")),
    )
    op.create_index(op.f("ix_preauth_sessions_expires_at"), "preauth_sessions", ["expires_at"])
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("object_type", sa.String(64), nullable=True),
        sa.Column("object_id", sa.String(128), nullable=True),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column(
            "details", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"], ["users.id"], name=op.f("fk_audit_logs_actor_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_logs")),
    )
    op.create_index(op.f("ix_audit_logs_occurred_at"), "audit_logs", ["occurred_at"])
    op.create_index(op.f("ix_audit_logs_actor_id"), "audit_logs", ["actor_id"])
    op.create_index(op.f("ix_audit_logs_request_id"), "audit_logs", ["request_id"])

    # aegis_app is provisioned by infra/postgres/010-runtime-role.sh, never owns
    # tables and receives no DDL, TRUNCATE, REFERENCES or TRIGGER privilege.
    op.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC, aegis_app")
    op.execute("GRANT USAGE ON SCHEMA public TO aegis_app")
    op.execute(
        "REVOKE ALL ON TABLE users, auth_sessions, refresh_tokens, preauth_sessions, audit_logs FROM PUBLIC, aegis_app"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE users, auth_sessions, refresh_tokens, preauth_sessions TO aegis_app"
    )
    op.execute("GRANT SELECT, INSERT ON TABLE audit_logs TO aegis_app")
    op.execute("GRANT SELECT ON TABLE alembic_version TO aegis_app")


def downgrade() -> None:
    # Dropping each table also removes its indexes, constraints and grants.
    op.drop_table("audit_logs")
    op.drop_table("preauth_sessions")
    op.drop_table("refresh_tokens")
    op.drop_table("auth_sessions")
    op.drop_table("users")
