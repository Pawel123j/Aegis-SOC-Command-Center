"""Apply explicit revisions with a separate database owner credential."""

import os
from logging.config import fileConfig

from alembic import context
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.infrastructure.database import Base
from app.modules.alerts import models as alert_models  # noqa: F401
from app.modules.audit.models import AuditLog  # noqa: F401
from app.modules.auth.models import AuthSession, PreAuthSession, RefreshToken  # noqa: F401
from app.modules.detections import models as detection_models  # noqa: F401
from app.modules.ingestion import models as ingestion_models  # noqa: F401
from app.modules.normalization import models as normalization_models  # noqa: F401
from app.modules.users.models import User  # noqa: F401

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def database_url() -> str:
    value = os.environ.get("AEGIS_DATABASE_URL", "")
    try:
        Settings.validate_database_url(SecretStr(value))
    except ValueError:
        raise RuntimeError("A valid owner AEGIS_DATABASE_URL is required for migrations") from None
    return value


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def migrate_connection(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    supplied_connection = config.attributes.get("connection")
    if supplied_connection is not None:
        migrate_connection(supplied_connection)
        return
    engine = create_engine(
        database_url(),
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"connect_timeout": 5, "options": "-c timezone=UTC"},
    )
    try:
        with engine.connect() as connection:
            migrate_connection(connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
