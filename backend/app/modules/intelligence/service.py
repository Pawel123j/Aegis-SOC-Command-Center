"""Verified local revisions, controlled publication and bounded catalog reads."""

import hashlib
import hmac
from copy import deepcopy
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.modules.audit.service import append_audit
from app.modules.ingestion.schemas import canonical_json
from app.modules.intelligence.models import IOCIdentity, IOCRevision
from app.modules.intelligence.normalization import NORMALIZATION_VERSION, normalize_indicator
from app.modules.intelligence.schemas import (
    IOCFilters,
    IOCInput,
    IOCPatch,
    IOCView,
    RevisionDocument,
)

MAX_IOCS = 1000
MAX_REVISIONS = 50
MAX_IMPORT = 100


def normalized_input(data: IOCInput) -> IOCInput:
    try:
        value = normalize_indicator(data.type, data.value)
    except ValueError:
        raise ApiError(
            422, "indicator_invalid", "Indicator value is invalid for its type"
        ) from None
    return data.model_copy(update={"value": value})


def revision_document(row: IOCRevision) -> dict[str, Any]:
    """Return the exact original document only after validating all immutable proof."""
    try:
        document = RevisionDocument.model_validate(row.document)
        canonical = canonical_json(row.document)
        if (
            canonical.decode("utf-8") != row.canonical_document
            or not hmac.compare_digest(hashlib.sha256(canonical).hexdigest(), row.document_sha256)
            or document.ioc_id != row.ioc_id
            or document.revision_id != row.id
            or document.revision != row.revision
            or document.normalization_version != NORMALIZATION_VERSION
            or normalize_indicator(document.type, document.value) != document.value
            or document.canonical_value != document.value
            or document.model_dump(mode="json") != row.document
        ):
            raise ValueError("revision proof mismatch")
    except (KeyError, TypeError, ValueError):
        raise ValueError("intelligence_revision_integrity_mismatch") from None
    return deepcopy(row.document)


def current_revision(db: Session, identity: IOCIdentity) -> IOCRevision:
    row = (
        db.get(IOCRevision, identity.current_revision_id) if identity.current_revision_id else None
    )
    if row is None:
        raise ValueError("intelligence_revision_integrity_mismatch")
    document = revision_document(row)
    if (
        row.ioc_id != identity.id
        or row.revision != identity.version
        or document["type"] != identity.kind
        or document["value"] != identity.canonical_value
        or identity.normalization_version != NORMALIZATION_VERSION
    ):
        raise ValueError("intelligence_revision_integrity_mismatch")
    return row


def ioc_view(identity: IOCIdentity, row: IOCRevision) -> IOCView:
    try:
        document = revision_document(row)
        if (
            row.ioc_id != identity.id
            or row.revision != identity.version
            or document["type"] != identity.kind
            or document["value"] != identity.canonical_value
            or identity.normalization_version != NORMALIZATION_VERSION
        ):
            raise ValueError("revision pointer mismatch")
        values = {key: document[key] for key in IOCInput.model_fields}
        return IOCView(
            **values,
            id=identity.id,
            canonical_value=identity.canonical_value,
            normalization_version=identity.normalization_version,
            revision=row.revision,
            revision_id=row.id,
            document_sha256=row.document_sha256,
            version=identity.version,
            created_at=identity.created_at,
            created_by=identity.created_by,
            updated_at=row.created_at,
            updated_by=row.created_by,
        )
    except (KeyError, TypeError, ValueError):
        raise ApiError(
            409, "intelligence_revision_integrity_mismatch", "Stored IOC revision proof is invalid"
        ) from None


def active_iocs(db: Session) -> list[IOCRevision]:
    pairs = db.execute(
        select(IOCIdentity, IOCRevision)
        .join(IOCRevision, IOCRevision.id == IOCIdentity.current_revision_id)
        .where(IOCRevision.document["active"].as_boolean().is_(True))
        .order_by(IOCIdentity.id)
        .limit(MAX_IOCS + 1)
    ).all()
    if len(pairs) > MAX_IOCS:
        raise ValueError("intelligence_catalog_limit")
    result = []
    for identity, revision in pairs:
        row = current_revision(db, identity)
        if row.id != revision.id:
            raise ValueError("intelligence_revision_integrity_mismatch")
        result.append(row)
    return result


def record(db: Session, identifier: UUID, *, locked: bool = False) -> IOCIdentity:
    statement = select(IOCIdentity).where(IOCIdentity.id == identifier)
    if locked:
        # The caller holds ADMIN_LOCK_ID, also taken by the publication function.
        # Runtime cannot lock rows with FOR UPDATE because it has no UPDATE grant.
        statement = statement.execution_options(populate_existing=True)
    row = db.scalar(statement)
    if row is None:
        raise ApiError(404, "ioc_not_found", "IOC not found")
    return row


def _current(db: Session, identity: IOCIdentity) -> IOCRevision:
    try:
        return current_revision(db, identity)
    except (KeyError, TypeError, ValueError):
        raise ApiError(
            409, "intelligence_revision_integrity_mismatch", "Stored IOC revision proof is invalid"
        ) from None


def _publish(
    db: Session, identity: IOCIdentity, data: IOCInput, actor: UUID, request_id: str
) -> IOCRevision:
    revision = identity.version + 1
    if revision > MAX_REVISIONS:
        raise ApiError(409, "ioc_revision_limit", "IOC revision limit reached")
    identifier = uuid4()
    document = RevisionDocument(
        **data.model_dump(),
        ioc_id=identity.id,
        revision_id=identifier,
        revision=revision,
        canonical_value=identity.canonical_value,
    ).model_dump(mode="json")
    canonical = canonical_json(document)
    row = IOCRevision(
        id=identifier,
        ioc_id=identity.id,
        revision=revision,
        document=document,
        canonical_document=canonical.decode("utf-8"),
        document_sha256=hashlib.sha256(canonical).hexdigest(),
        created_by=actor,
    )
    db.add(row)
    db.flush()
    db.execute(
        text("SELECT public.aegis_select_ioc_revision(:ioc,:revision,:actor)"),
        {"ioc": identity.id, "revision": row.id, "actor": actor},
    )
    db.refresh(identity)
    append_audit(
        db,
        action="intelligence.created" if revision == 1 else "intelligence.revised",
        outcome="success",
        request_id=request_id,
        actor_id=actor,
        object_type="ioc",
        object_id=str(identity.id),
        details={
            "revision": revision,
            "revision_id": str(row.id),
            "document_sha256": row.document_sha256,
            "type": data.type,
            "active": data.active,
        },
    )
    return row


def create_ioc(
    db: Session, data: IOCInput, *, actor: UUID, request_id: str
) -> tuple[IOCView, bool]:
    data = normalized_input(data)
    identity = db.scalar(
        select(IOCIdentity).where(
            IOCIdentity.kind == data.type, IOCIdentity.canonical_value == data.value
        )
    )
    if identity is not None:
        current = _current(db, identity)
        document = revision_document(current)
        if {key: document[key] for key in IOCInput.model_fields} != data.model_dump(mode="json"):
            raise ApiError(409, "ioc_exists", "IOC already exists; change its metadata explicitly")
        return ioc_view(identity, current), False
    if int(db.scalar(select(func.count()).select_from(IOCIdentity)) or 0) >= MAX_IOCS:
        raise ApiError(409, "ioc_catalog_limit", "IOC catalog limit reached")
    identity = IOCIdentity(
        kind=data.type,
        canonical_value=data.value,
        normalization_version=NORMALIZATION_VERSION,
        created_by=actor,
    )
    db.add(identity)
    db.flush()
    row = _publish(db, identity, data, actor, request_id)
    return ioc_view(identity, row), True


def patch_ioc(
    db: Session, identity: IOCIdentity, data: IOCPatch, *, actor: UUID, request_id: str
) -> IOCView:
    current = _current(db, identity)
    document = revision_document(current)
    prior = {key: document[key] for key in IOCInput.model_fields}
    try:
        updated = IOCInput.model_validate({**prior, **data.model_dump(exclude_unset=True)})
    except ValueError:
        raise ApiError(422, "ioc_metadata_invalid", "IOC metadata is invalid") from None
    if updated.model_dump(mode="json") == prior:
        return ioc_view(identity, current)
    return ioc_view(identity, _publish(db, identity, updated, actor, request_id))


_LIST = text("""
WITH filtered AS MATERIALIZED (
 SELECT i.id,i.created_at,i.current_revision_id FROM public.ioc_identities i
 JOIN public.ioc_revisions r ON r.id=i.current_revision_id
 WHERE i.created_at<=:anchor
  AND (CAST(:kind AS text) IS NULL OR i.kind=:kind)
  AND (CAST(:reputation AS text) IS NULL OR r.document->>'reputation'=:reputation)
  AND (CAST(:active AS boolean) IS NULL OR (r.document->>'active')::boolean=:active)
  AND (CAST(:q AS text) IS NULL OR strpos(lower(i.canonical_value),lower(:q))>0
    OR strpos(lower(r.document->>'source'),lower(:q))>0
    OR strpos(lower(r.document->>'description'),lower(:q))>0)
), page AS (
 SELECT * FROM filtered WHERE (CAST(:after_time AS timestamptz) IS NULL OR
  (created_at,id)<(CAST(:after_time AS timestamptz),CAST(:after_id AS uuid)))
 ORDER BY created_at DESC,id DESC LIMIT :page_size
)
SELECT jsonb_build_object('total',(SELECT count(*) FROM filtered),'items',COALESCE((
 SELECT jsonb_agg(jsonb_build_object('identity',to_jsonb(i),'revision',to_jsonb(r))
  ORDER BY i.created_at DESC,i.id DESC) FROM page p
 JOIN public.ioc_identities i ON i.id=p.id JOIN public.ioc_revisions r ON r.id=p.current_revision_id
),'[]'::jsonb))
""")


def catalogue(
    db: Session, filters: IOCFilters, anchor: datetime, after: tuple[datetime, UUID] | None
) -> tuple[list[IOCView], int]:
    db.execute(text("SET LOCAL statement_timeout='3000ms'"))
    result: Any = db.scalar(
        _LIST,
        {
            "anchor": anchor,
            "kind": filters.kind,
            "reputation": filters.reputation,
            "active": filters.active,
            "q": filters.q,
            "after_time": after[0] if after else None,
            "after_id": after[1] if after else None,
            "page_size": filters.limit + 1,
        },
    )
    assert isinstance(result, dict)
    if result["total"] > MAX_IOCS:
        raise ApiError(503, "ioc_catalog_limit", "IOC catalog exceeds supported bounds")
    views = []
    for item in result["items"]:
        identity = dict(item["identity"])
        for key in ("id", "created_by", "current_revision_id"):
            identity[key] = UUID(identity[key])
        identity["created_at"] = datetime.fromisoformat(identity["created_at"])
        revision = dict(item["revision"])
        for key in ("id", "ioc_id", "created_by"):
            revision[key] = UUID(revision[key])
        revision["created_at"] = datetime.fromisoformat(revision["created_at"])
        views.append(ioc_view(IOCIdentity(**identity), IOCRevision(**revision)))
    return views, result["total"]
