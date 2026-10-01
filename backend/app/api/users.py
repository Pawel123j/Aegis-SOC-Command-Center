"""Administrator account management with optimistic and last-admin protection."""

from datetime import datetime
from typing import Annotated, Self
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from sqlalchemy import func, select, update

from app.api.dependencies import DB, Principal, lock_authority, require
from app.core.errors import ApiError
from app.core.permissions import Permission, Role
from app.core.security import hash_password, utcnow
from app.modules.audit.service import append_audit
from app.modules.auth.models import AuthSession
from app.modules.users.models import User, normalize_username

router = APIRouter(prefix="/api/v1/users", tags=["users"])
Admin = Annotated[Principal, Depends(require(Permission.USERS_MANAGE))]
UserReader = Annotated[Principal, Depends(require(Permission.USERS_READ))]


class UserView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    username: str
    role: Role
    enabled: bool
    version: int
    created_at: datetime


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64)
    password: SecretStr = Field(min_length=15, max_length=128)
    role: Role

    @field_validator("username")
    @classmethod
    def normalized(cls, value: str) -> str:
        return normalize_username(value)


class UserPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Role | None = None
    enabled: bool | None = Field(default=None, strict=True)
    password: SecretStr | None = Field(default=None, min_length=15, max_length=128)

    @model_validator(mode="after")
    def nonempty(self) -> Self:
        if not self.model_fields_set or any(
            getattr(self, key) is None for key in self.model_fields_set
        ):
            raise ValueError("Provide at least one non-null change")
        return self


def lock_administration(db: DB, principal: Principal, request: Request) -> None:
    lock_authority(db, principal, Permission.USERS_MANAGE, request)


@router.get("")
def users(
    db: DB,
    principal: UserReader,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: UUID | None = None,
) -> dict[str, object]:
    query = select(User).order_by(User.id).limit(limit + 1)
    if cursor:
        query = query.where(User.id > cursor)
    records = list(db.scalars(query))
    return {
        "items": [UserView.model_validate(user) for user in records[:limit]],
        "next_cursor": str(records[limit - 1].id) if len(records) > limit else None,
    }


@router.post("", status_code=201, response_model=UserView)
def create_user(
    data: UserCreate, request: Request, response: Response, db: DB, principal: Admin
) -> User:
    lock_administration(db, principal, request)
    user = User(
        username=data.username,
        password_hash=hash_password(data.password.get_secret_value()),
        role=data.role,
    )
    db.add(user)
    db.flush()
    append_audit(
        db,
        action="user.created",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=principal.user.id,
        object_type="user",
        object_id=str(user.id),
        details={"username": user.username, "role": user.role.value},
    )
    db.commit()
    response.headers["ETag"] = f'"{user.version}"'
    return user


@router.patch("/{user_id}", response_model=UserView)
def patch_user(
    user_id: UUID,
    data: UserPatch,
    request: Request,
    response: Response,
    db: DB,
    principal: Admin,
    if_match: Annotated[str | None, Header()] = None,
) -> User:
    if if_match is None:
        raise ApiError(428, "version_required", "If-Match is required")
    lock_administration(db, principal, request)
    # Serialize account updates/login without blocking FK KEY SHARE locks from
    # refresh/logout audit inserts while their session row is locked.
    user = db.scalar(select(User).where(User.id == user_id).with_for_update(key_share=True))
    if user is None:
        raise ApiError(404, "not_found", "User not found")
    if if_match != f'"{user.version}"':
        raise ApiError(412, "version_conflict", "Refresh the resource before updating")
    removes_admin = (
        user.role == Role.ADMIN
        and user.enabled
        and (data.enabled is False or data.role not in (None, Role.ADMIN))
    )
    if removes_admin:
        count = db.scalar(
            select(func.count())
            .select_from(User)
            .where(User.role == Role.ADMIN, User.enabled.is_(True))
        )
        if count is None or count <= 1:
            raise ApiError(409, "last_admin", "At least one active administrator is required")
    before = {"role": user.role.value, "enabled": user.enabled}
    if data.role is not None:
        user.role = data.role
    if data.enabled is not None:
        user.enabled = data.enabled
    if data.password is not None:
        user.password_hash = hash_password(data.password.get_secret_value())
    user.updated_at = utcnow()
    # Revocation also prevents a later re-enable from reviving old access tokens.
    db.execute(
        update(AuthSession)
        .where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
    append_audit(
        db,
        action="user.updated",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=principal.user.id,
        object_type="user",
        object_id=str(user.id),
        details={
            "before": before,
            "after": {"role": user.role.value, "enabled": user.enabled},
            "password_changed": data.password is not None,
        },
    )
    db.commit()
    response.headers["ETag"] = f'"{user.version}"'
    return user
