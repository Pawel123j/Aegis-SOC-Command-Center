"""Signed, user/query-bound keyset cursors for bounded PostgreSQL case reads."""

import base64
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.errors import ApiError
from app.core.security import utcnow
from app.modules.ingestion.schemas import canonical_json


class CursorCodec:
    def __init__(self, secret: str, namespace: str, scope: dict[str, Any]) -> None:
        self.key = hmac.digest(secret.encode(), namespace.encode(), "sha256")
        self.scope = hashlib.sha256(canonical_json(scope)).hexdigest()

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)

    def read(self, cursor: str | None) -> tuple[datetime, tuple[datetime, UUID] | None]:
        if cursor is None:
            return utcnow(), None
        try:
            parts = cursor.split(".")
            if len(parts) != 2:
                raise ValueError
            payload, signature = (self._decode(part) for part in parts)
            if not hmac.compare_digest(signature, hmac.digest(self.key, payload, "sha256")):
                raise ValueError
            content = json.loads(payload)
            if (
                set(content) != {"scope", "anchor", "time", "id", "expires", "v"}
                or content["v"] != 1
                or type(content["expires"]) is not int
                or content["expires"] < int(time.time())
                or content["scope"] != self.scope
            ):
                raise ValueError
            anchor, after = (datetime.fromisoformat(content[key]) for key in ("anchor", "time"))
            if (
                any(
                    value.tzinfo is None or value.utcoffset() != timedelta(0)
                    for value in (anchor, after)
                )
                or after > anchor
            ):
                raise ValueError
            return anchor, (after, UUID(content["id"]))
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
            raise ApiError(422, "invalid_cursor", "Incident cursor is invalid") from None

    def next(self, anchor: datetime, moment: datetime, identifier: UUID) -> str:
        payload = canonical_json(
            {
                "v": 1,
                "scope": self.scope,
                "anchor": anchor.astimezone(UTC).isoformat(),
                "time": moment.astimezone(UTC).isoformat(),
                "id": str(identifier),
                "expires": int(time.time()) + 900,
            }
        )
        return self._encode(payload) + "." + self._encode(hmac.digest(self.key, payload, "sha256"))
