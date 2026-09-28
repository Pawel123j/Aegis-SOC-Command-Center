"""User identity and optimistic versioning shared by authentication and administration."""

import re
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, Enum, Integer, String, text
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.permissions import Role
from app.infrastructure.database import Base, utcnow


def normalize_username(value: str) -> str:
    normalized = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,63}", normalized):
        raise ValueError(
            "username must contain 3–64 ASCII letters, digits, dots, dashes or underscores"
        )
    return normalized


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("username ~ '^[a-z0-9][a-z0-9_.-]{2,63}$'", name="username_normalized"),
        CheckConstraint("version >= 1", name="positive_version"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[Role] = mapped_column(
        Enum(
            Role,
            native_enum=False,
            create_constraint=True,
            name="user_role",
            values_callable=lambda values: [value.value for value in values],
        ),
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, server_default=text("now()")
    )
    version: Mapped[int] = mapped_column(Integer, default=1, server_default=text("1"))

    __mapper_args__ = {"version_id_col": version}

    @validates("username")
    def _normalize_username(self, key: str, value: str) -> str:
        return normalize_username(value)
