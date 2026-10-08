"""Bound request bytes before parsing; never echo rejected payloads."""

import json
import math
from typing import Any

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


def validate_ingest_json(body: bytes) -> None:
    # Check structural nesting without recursion before handing bytes to a JSON
    # decoder. Brackets inside strings do not contribute to the depth budget.
    depth, in_string, escaped = 0, False, False
    for char in body:
        if in_string:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                in_string = False
        elif char == 34:
            in_string = True
        elif char in (91, 123):
            depth += 1
            if depth > 20:
                raise ValueError("JSON nesting limit exceeded")
        elif char in (93, 125):
            depth -= 1

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def finite_number(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("finite JSON numbers required")
        return result

    json.loads(
        body.decode("utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=finite_number,
        parse_float=finite_number,
    )


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, limit: int = 65536) -> None:
        self.app, self.limit = app, limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        is_ingest = scope["method"] == "POST" and scope["path"].rstrip("/") == "/api/v1/events"
        is_sigma = scope["method"] == "POST" and scope["path"].startswith("/api/v1/sigma/")
        is_intelligence = scope["path"].startswith("/api/v1/intelligence/")
        limit = 1048576 if is_ingest else self.limit
        if is_sigma:
            limit = 1048576 if scope["path"].rstrip("/") == "/api/v1/sigma/test" else 262144
        if is_intelligence and scope["path"].rstrip("/") == "/api/v1/intelligence/import":
            limit = 1048576
        content_type = headers.get(b"content-type", b"").split(b";")[0].strip().lower()
        if content_type not in {b"", b"application/json"} or b"content-encoding" in headers:
            await self.reject(scope, receive, send, 415, "json_required")
            return
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            # Bodyless refresh/logout need no Content-Type. Any payload still
            # requires JSON, including when Content-Length is absent or forged.
            if size and not content_type:
                await self.reject(scope, receive, send, 415, "json_required")
                return
            if size > limit:
                await self.reject(scope, receive, send, 413, "body_too_large")
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        is_soar = scope["path"].startswith(("/api/v1/playbooks", "/api/v1/playbook-runs"))
        if is_ingest or is_sigma or is_intelligence or is_soar:
            try:
                validate_ingest_json(body)
            except (ValueError, RecursionError):
                await self.reject(scope, receive, send, 422, "validation_error")
                return
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    async def reject(
        self, scope: Scope, receive: Receive, send: Send, status: int, code: str
    ) -> None:
        response = JSONResponse(
            {
                "code": code,
                "message": "Request body rejected",
                "request_id": scope.get("state", {}).get("request_id", ""),
            },
            status_code=status,
        )
        await response(scope, receive, send)
