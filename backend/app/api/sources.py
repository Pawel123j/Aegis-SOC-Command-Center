"""Administrator enrollment and revocation of dedicated ingestion credentials."""

from datetime import datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select, update

from app.api.dependencies import DB, Principal, require
from app.api.users import lock_administration
from app.core.errors import ApiError
from app.core.permissions import Permission
from app.core.security import random_token, token_hash, utcnow
from app.modules.audit.service import append_audit
from app.modules.ingestion.models import IngestionSource, SourceCredential
from app.modules.ingestion.schemas import SourceType

router = APIRouter(prefix="/api/v1/sources", tags=["sources"])
SourceAdmin = Annotated[Principal, Depends(require(Permission.SOURCES_MANAGE))]
CredentialScope = Literal["events:write", "events:status"]


def default_scopes() -> list[CredentialScope]:
    return ["events:write", "events:status"]


class SourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=128)
    source_types: list[SourceType] = Field(min_length=1, max_length=6)
    timezone: str = Field(default="UTC", min_length=1, max_length=64)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("a valid Unicode source name is required") from None
        if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("a nonempty source name without control characters is required")
        return value

    @field_validator("source_types")
    @classmethod
    def distinct_types(cls, value: list[SourceType]) -> list[SourceType]:
        if len(set(value)) != len(value):
            raise ValueError("source types must be distinct")
        return value

    @field_validator("timezone")
    @classmethod
    def known_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("an IANA timezone is required") from None
        return value


class SourcePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = Field(strict=True)


class CredentialCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scopes: list[CredentialScope] = Field(
        default_factory=default_scopes, min_length=1, max_length=2
    )
    expires_in_days: int = Field(default=30, ge=1, le=90, strict=True)

    @field_validator("scopes")
    @classmethod
    def distinct_scopes(cls, value: list[CredentialScope]) -> list[CredentialScope]:
        if len(set(value)) != len(value):
            raise ValueError("scopes must be distinct")
        return value


class SourceView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    name: str
    dataset_id: UUID
    mode: str
    run_id: UUID
    source_types: list[str]
    timezone: str
    enabled: bool
    version: int
    created_at: datetime


def lock_source(db: DB, source_id: UUID) -> IngestionSource:
    source = db.scalar(
        select(IngestionSource)
        .where(IngestionSource.id == source_id)
        .with_for_update(key_share=True)
        .execution_options(populate_existing=True)
    )
    if source is None:
        raise ApiError(404, "not_found", "Source not found")
    return source


def issue_credential(
    db: DB, source: IngestionSource, data: CredentialCreate
) -> tuple[SourceCredential, str]:
    raw = f"aegis_ingest_{random_token()}"
    credential = SourceCredential(
        id=uuid4(),
        source_id=source.id,
        secret_hash=token_hash(raw),
        scopes=sorted(data.scopes),
        created_at=utcnow(),
        expires_at=utcnow() + timedelta(days=data.expires_in_days),
    )
    db.add(credential)
    db.flush()
    return credential, raw


def credential_view(credential: SourceCredential, token: str | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "id": credential.id,
        "scopes": credential.scopes,
        "expires_at": credential.expires_at,
        "revoked_at": credential.revoked_at,
    }
    if token is not None:
        result["token"] = token
    return result


@router.get("")
def list_sources(
    db: DB,
    principal: SourceAdmin,
    response: Response,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: UUID | None = None,
) -> dict[str, object]:
    query = select(IngestionSource).order_by(IngestionSource.id).limit(limit + 1)
    if cursor:
        query = query.where(IngestionSource.id > cursor)
    records = list(db.scalars(query))
    response.headers["Cache-Control"] = "no-store"
    return {
        "items": [SourceView.model_validate(source) for source in records[:limit]],
        "next_cursor": str(records[limit - 1].id) if len(records) > limit else None,
    }


@router.post("", status_code=201)
def create_source(
    data: SourceCreate, request: Request, response: Response, db: DB, principal: SourceAdmin
) -> dict[str, object]:
    lock_administration(db, principal)
    source = IngestionSource(
        id=uuid4(),
        name=data.name,
        dataset_id=uuid4(),
        mode="live",
        run_id=UUID(int=0),
        source_types=[value.value for value in data.source_types],
        timezone=data.timezone,
        enabled=True,
    )
    db.add(source)
    db.flush()
    credential, raw = issue_credential(db, source, CredentialCreate())
    append_audit(
        db,
        action="source.created",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=principal.user.id,
        object_type="source",
        object_id=str(source.id),
        details={"source_types": source.source_types, "credential_id": str(credential.id)},
    )
    db.commit()
    response.headers.update({"Cache-Control": "no-store", "ETag": f'"{source.version}"'})
    return {
        "source": SourceView.model_validate(source),
        "credential": credential_view(credential, raw),
    }


@router.get("/{source_id}")
def get_source(
    source_id: UUID, response: Response, db: DB, principal: SourceAdmin
) -> dict[str, object]:
    source = db.get(IngestionSource, source_id)
    if source is None:
        raise ApiError(404, "not_found", "Source not found")
    credentials = list(
        db.scalars(
            select(SourceCredential)
            .where(SourceCredential.source_id == source_id)
            .order_by(SourceCredential.created_at.desc(), SourceCredential.id)
            .limit(100)
        )
    )
    response.headers.update({"Cache-Control": "no-store", "ETag": f'"{source.version}"'})
    return {
        "source": SourceView.model_validate(source),
        "credentials": [credential_view(credential) for credential in credentials],
    }


@router.patch("/{source_id}", response_model=SourceView)
def patch_source(
    source_id: UUID,
    data: SourcePatch,
    request: Request,
    response: Response,
    db: DB,
    principal: SourceAdmin,
    if_match: Annotated[str | None, Header()] = None,
) -> IngestionSource:
    if if_match is None:
        raise ApiError(428, "version_required", "If-Match is required")
    lock_administration(db, principal)
    source = lock_source(db, source_id)
    if if_match != f'"{source.version}"':
        raise ApiError(412, "version_conflict", "Refresh the resource before updating")
    before = source.enabled
    source.enabled = data.enabled
    if not source.enabled:
        db.execute(
            update(SourceCredential)
            .where(SourceCredential.source_id == source.id, SourceCredential.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
    append_audit(
        db,
        action="source.updated",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=principal.user.id,
        object_type="source",
        object_id=str(source.id),
        details={"enabled_before": before, "enabled_after": source.enabled},
    )
    db.commit()
    response.headers.update({"Cache-Control": "no-store", "ETag": f'"{source.version}"'})
    return source


@router.post("/{source_id}/credentials", status_code=201)
def create_credential(
    source_id: UUID,
    data: CredentialCreate,
    request: Request,
    response: Response,
    db: DB,
    principal: SourceAdmin,
) -> dict[str, object]:
    lock_administration(db, principal)
    source = lock_source(db, source_id)
    if not source.enabled:
        raise ApiError(409, "source_disabled", "Enable the source before issuing credentials")
    credential, raw = issue_credential(db, source, data)
    append_audit(
        db,
        action="source.credential_created",
        outcome="success",
        request_id=request.state.request_id,
        actor_id=principal.user.id,
        object_type="source",
        object_id=str(source.id),
        details={"credential_id": str(credential.id), "scopes": credential.scopes},
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return credential_view(credential, raw)


@router.delete("/{source_id}/credentials/{credential_id}", status_code=204)
def revoke_credential(
    source_id: UUID,
    credential_id: UUID,
    request: Request,
    response: Response,
    db: DB,
    principal: SourceAdmin,
) -> None:
    lock_administration(db, principal)
    lock_source(db, source_id)
    credential = db.scalar(
        select(SourceCredential)
        .where(SourceCredential.id == credential_id, SourceCredential.source_id == source_id)
        .with_for_update()
    )
    if credential is None:
        raise ApiError(404, "not_found", "Credential not found")
    if credential.revoked_at is None:
        credential.revoked_at = utcnow()
        append_audit(
            db,
            action="source.credential_revoked",
            outcome="success",
            request_id=request.state.request_id,
            actor_id=principal.user.id,
            object_type="source",
            object_id=str(source_id),
            details={"credential_id": str(credential_id)},
        )
        db.commit()
    response.headers["Cache-Control"] = "no-store"
