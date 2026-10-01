"""Stable search windows and expiring cursors bound to the user and full query scope."""

import base64
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.config import Settings
from app.modules.events.clickhouse import ClickHouseEvents
from app.modules.events.schemas import SearchRequest, SearchResult, check_window
from app.modules.ingestion.schemas import canonical_json


class CursorError(ValueError):
    pass


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, UnicodeError):
        raise CursorError("invalid_cursor") from None


def _scope(request: SearchRequest, user_id: UUID, database: str) -> str:
    value = request.model_dump(mode="json", exclude={"cursor", "from_", "to"})
    value.update({"user_id": str(user_id), "database": database})
    return hashlib.sha256(canonical_json(value)).hexdigest()


class CursorCodec:
    def __init__(self, settings: Settings) -> None:
        self.key = hmac.digest(
            settings.jwt_secret.get_secret_value().encode(), b"aegis-event-cursor-v1", "sha256"
        )

    def issue(
        self,
        request: SearchRequest,
        user_id: UUID,
        database: str,
        start: datetime,
        end: datetime,
        after: tuple[datetime, UUID],
    ) -> str:
        payload = canonical_json(
            {
                "v": 1,
                "scope": _scope(request, user_id, database),
                "from": start.isoformat(),
                "to": end.isoformat(),
                "time": after[0].isoformat(),
                "id": str(after[1]),
                "expires": int(time.time()) + 900,
            }
        )
        return _encode(payload) + "." + _encode(hmac.digest(self.key, payload, "sha256"))

    def read(
        self,
        request: SearchRequest,
        user_id: UUID,
        database: str,
    ) -> tuple[datetime, datetime, tuple[datetime, UUID]]:
        try:
            parts = (request.cursor or "").split(".")
            if len(parts) != 2:
                raise ValueError
            payload, signature = (_decode(part) for part in parts)
            if not hmac.compare_digest(signature, hmac.digest(self.key, payload, "sha256")):
                raise ValueError
            content = json.loads(payload)
            if (
                set(content) != {"v", "scope", "from", "to", "time", "id", "expires"}
                or content["v"] != 1
                or type(content["expires"]) is not int
                or content["expires"] < int(time.time())
                or content["scope"] != _scope(request, user_id, database)
            ):
                raise ValueError
            start, end, after = (
                datetime.fromisoformat(content[key]) for key in ("from", "to", "time")
            )
            if any(
                value.tzinfo is None or value.utcoffset() != timedelta(0)
                for value in (start, end, after)
            ):
                raise ValueError
            check_window(start, end)
            if not start <= after < end:
                raise ValueError
            if (request.from_ is not None and request.from_ != start) or (
                request.to is not None and request.to != end
            ):
                raise ValueError
            return start, end, (after, UUID(content["id"]))
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
            raise CursorError("invalid_cursor") from None


def search(
    settings: Settings,
    request: SearchRequest,
    user_id: UUID,
    archive: ClickHouseEvents | None = None,
) -> SearchResult:
    store = archive or ClickHouseEvents(settings)
    codec = CursorCodec(settings)
    after = None
    if request.cursor:
        start, end, after = codec.read(request, user_id, store.database)
    else:
        end = request.to or datetime.now(UTC)
        start = request.from_ or end - timedelta(hours=24)
        check_window(start, end)
    documents, total = store.search(request, start, end, after)
    cursor = None
    if len(documents) > request.limit:
        documents = documents[: request.limit]
        last: dict[str, Any] = documents[-1]
        cursor = codec.issue(
            request,
            user_id,
            store.database,
            start,
            end,
            (
                datetime.fromisoformat(last["timestamp"].replace("Z", "+00:00")),
                UUID(last["event_id"]),
            ),
        )
    return SearchResult.model_validate(
        {
            "items": documents,
            "total": total,
            "next_cursor": cursor,
            "from": start,
            "to": end,
        }
    )
