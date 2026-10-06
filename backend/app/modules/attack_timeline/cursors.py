"""Signed current-view cursors; observed time is independent of the server clock."""

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.errors import ApiError
from app.modules.ingestion.schemas import canonical_json

NAMESPACE = "attack-timeline-v1"
TTL_SECONDS = 900


@dataclass(frozen=True)
class Position:
    fingerprint: str
    moment: datetime
    event_id: UUID
    issued: int
    expires: int


class TimelineCursor:
    def __init__(self, secret: str, scope: dict[str, Any]) -> None:
        self.key = hmac.digest(secret.encode(), NAMESPACE.encode(), "sha256")
        self.scope = hashlib.sha256(canonical_json(scope)).hexdigest()

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)

    def read(self, cursor: str | None) -> Position | None:
        if cursor is None:
            return None
        try:
            if len(cursor) > 4096:
                raise ValueError
            parts = cursor.split(".")
            if len(parts) != 2:
                raise ValueError
            payload, signature = (self._decode(part) for part in parts)
            if not hmac.compare_digest(signature, hmac.digest(self.key, payload, "sha256")):
                raise ValueError
            data = json.loads(payload)
            now = int(time.time())
            if (
                set(data) != {"v", "scope", "fingerprint", "time", "id", "issued", "expires"}
                or type(data["v"]) is not int
                or data["v"] != 1
                or data["scope"] != self.scope
                or type(data["issued"]) is not int
                or type(data["expires"]) is not int
                or data["issued"] > now
                or data["expires"] != data["issued"] + TTL_SECONDS
                or now >= data["expires"]
                or not isinstance(data["fingerprint"], str)
                or re.fullmatch(r"[0-9a-f]{64}", data["fingerprint"]) is None
            ):
                raise ValueError
            moment = datetime.fromisoformat(data["time"])
            identifier = UUID(data["id"])
            if moment.tzinfo is None or moment.utcoffset() != timedelta(0):
                raise ValueError
            return Position(
                data["fingerprint"], moment, identifier, data["issued"], data["expires"]
            )
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, OverflowError):
            raise ApiError(422, "invalid_cursor", "Attack timeline cursor is invalid") from None

    def next(
        self,
        fingerprint: str,
        moment: datetime,
        identifier: UUID,
        previous: Position | None = None,
    ) -> str:
        issued = previous.issued if previous else int(time.time())
        payload = canonical_json(
            {
                "v": 1,
                "scope": self.scope,
                "fingerprint": fingerprint,
                "time": moment.astimezone(UTC).isoformat(),
                "id": str(identifier),
                "issued": issued,
                "expires": issued + TTL_SECONDS,
            }
        )
        return self._encode(payload) + "." + self._encode(hmac.digest(self.key, payload, "sha256"))
