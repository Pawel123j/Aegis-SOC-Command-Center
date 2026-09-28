"""Bound request bytes before parsing; never echo rejected payloads."""

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, limit: int = 65536) -> None:
        self.app, self.limit = app, limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
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
            if size > self.limit:
                await self.reject(scope, receive, send, 413, "body_too_large")
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
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
