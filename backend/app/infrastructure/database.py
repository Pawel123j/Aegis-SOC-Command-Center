"""PostgreSQL unit of work. Services explicitly decide when transactions commit."""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

from sqlalchemy import MetaData, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import Settings

ADMIN_LOCK_ID = 280334879059


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(table_name)s_%(column_0_name)s",
            "uq": "uq_%(table_name)s_%(column_0_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s",
        }
    )


class Database:
    def __init__(self, settings: Settings) -> None:
        self.engine = create_engine(
            settings.database_url.get_secret_value(),
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=5,
            pool_timeout=5,
            connect_args={
                "connect_timeout": 3,
                "options": "-c statement_timeout=5000 -c timezone=UTC",
            },
            hide_parameters=True,
        )
        self.sessions = sessionmaker(self.engine, expire_on_commit=False, autoflush=False)

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self.sessions() as session:
            yield session

    def close(self) -> None:
        self.engine.dispose()
