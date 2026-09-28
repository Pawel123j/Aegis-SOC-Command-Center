"""Rate-limit rejection, atomic command boundaries and untrusted proxy headers."""

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from fastapi import Request
from redis.exceptions import ConnectionError, ResponseError, TimeoutError

from app.core.errors import ApiError
from app.core.rate_limit import peer, rate_limit


@pytest.fixture
def make_request() -> Callable[..., Request]:
    def create(
        redis: Any = None,
        client: tuple[str, int] | None = ("192.0.2.10", 45000),
        headers: list[tuple[bytes, bytes]] | None = None,
    ) -> Request:
        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/v1/auth/login",
                "headers": headers or [],
                "client": client,
                "app": SimpleNamespace(state=SimpleNamespace(redis=redis)),
            }
        )

    return create


def test_boundary_uses_one_atomic_redis_call_per_attempt(
    make_request: Callable[..., Request],
) -> None:
    redis = Mock()
    redis.eval.side_effect = [[1, 60], [2, 57], [3, 42]]
    request = make_request(redis)
    rate_limit(request, "login", "192.0.2.10", maximum=2)
    rate_limit(request, "login", "192.0.2.10", maximum=2)
    with pytest.raises(ApiError) as error:
        rate_limit(request, "login", "192.0.2.10", maximum=2)
    assert error.value.status == 429
    assert error.value.code == "rate_limited"
    assert error.value.headers == {"Retry-After": "42"}
    assert len(redis.mock_calls) == 3
    assert all(call[0] == "eval" for call in redis.mock_calls)
    arguments = [call.args for call in redis.eval.call_args_list]
    assert arguments[0] == arguments[1] == arguments[2]
    assert arguments[0][1] == 1  # One key, updated and expired inside Redis.
    assert arguments[0][3] == 60


@pytest.mark.parametrize("ttl", [0, -1, -2])
def test_retry_after_is_positive_during_expiry(
    make_request: Callable[..., Request], ttl: int
) -> None:
    redis = Mock()
    redis.eval.return_value = [5, ttl]
    with pytest.raises(ApiError) as error:
        rate_limit(make_request(redis), "login", "192.0.2.10", maximum=4)
    assert error.value.status == 429
    assert error.value.headers == {"Retry-After": "1"}


@pytest.mark.parametrize("failure", [ConnectionError, TimeoutError, ResponseError])
def test_redis_failure_denies_request_without_leaking_connection_details(
    make_request: Callable[..., Request], failure: type[Exception]
) -> None:
    redis = Mock()
    redis.eval.side_effect = failure("redis://:private-password@internal:6379")
    with pytest.raises(ApiError) as error:
        rate_limit(make_request(redis), "login", "192.0.2.10", maximum=4)
    assert error.value.status == 503
    assert error.value.code == "limiter_unavailable"
    assert error.value.message == "Service temporarily unavailable"
    assert "private-password" not in str(error.value)


def test_limit_keys_isolate_categories_and_hash_identifiers(
    make_request: Callable[..., Request],
) -> None:
    redis = Mock()
    redis.eval.return_value = [1, 60]
    request = make_request(redis)
    for category, identity in [
        ("login", "sensitive-user@example.test"),
        ("preauth", "sensitive-user@example.test"),
        ("login", "another-user@example.test"),
    ]:
        rate_limit(request, category, identity, maximum=4)
    keys = [call.args[2] for call in redis.eval.call_args_list]
    assert len(set(keys)) == 3
    assert all("example.test" not in key and "user" not in key for key in keys)
    assert all(len(key.rsplit(":", 1)[1]) == 64 for key in keys)


@pytest.mark.parametrize(
    "headers",
    [
        [(b"x-forwarded-for", b"198.51.100.9")],
        [(b"forwarded", b"for=198.51.100.9;proto=https")],
        [(b"x-real-ip", b"198.51.100.9")],
        [(b"x-forwarded-for", b"198.51.100.9"), (b"x-forwarded-for", b"203.0.113.7")],
    ],
)
def test_peer_uses_transport_address_and_ignores_untrusted_headers(
    make_request: Callable[..., Request], headers: list[tuple[bytes, bytes]]
) -> None:
    assert peer(make_request(headers=headers)) == "192.0.2.10"


def test_missing_peer_does_not_fall_back_to_forwarded_header(
    make_request: Callable[..., Request],
) -> None:
    assert peer(make_request(client=None, headers=[(b"x-forwarded-for", b"198.51.100.9")])) == (
        "unknown"
    )
