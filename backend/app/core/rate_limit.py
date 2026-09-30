"""Redis fixed windows; atomic expiry and fail-closed when unavailable."""

from typing import Any

from fastapi import Request
from redis.exceptions import RedisError

from app.core.errors import ApiError
from app.core.security import token_hash

INCREMENT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return {count, redis.call('TTL', KEYS[1])}
"""


def rate_limit(
    request: Request, category: str, identity: str, maximum: int, window_seconds: int = 60
) -> None:
    key = f"aegis:limit:{category}:{token_hash(identity)}"
    try:
        result: Any = request.app.state.redis.eval(INCREMENT, 1, key, window_seconds)
    except RedisError:
        raise ApiError(503, "limiter_unavailable", "Service temporarily unavailable") from None
    if int(result[0]) > maximum:
        raise ApiError(
            429, "rate_limited", "Too many requests", {"Retry-After": str(max(1, int(result[1])))}
        )


def peer(request: Request) -> str:
    # Uvicorn proxy headers are disabled; untrusted X-Forwarded-For never changes limits.
    return request.client.host if request.client else "unknown"
