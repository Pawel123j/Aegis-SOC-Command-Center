"""Security boundary regressions for credentials, signed tokens and log redaction."""

import io
import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import jwt
import pytest
from pydantic import SecretStr

from app.core import security
from app.core.config import Settings
from app.core.errors import ApiError
from app.core.observability import SafeJSONFormatter

TEST_KEY = "unit-only-signing-key-6b1fc89397b9452ea61354ae67c0310c-937fbca23d8f43c3"


@pytest.fixture
def security_settings() -> Settings:
    return Settings(
        database_url=SecretStr("postgresql+psycopg://unit:unit-db-72a9@localhost/unit"),
        redis_url=SecretStr("redis://:unit-cache-63bf@localhost:6379/0"),
        clickhouse_url="http://localhost:8123",
        clickhouse_user="unit",
        clickhouse_password=SecretStr("unit-ch-73c1"),
        jwt_secret=SecretStr(TEST_KEY),
        public_origin="https://soc.example.test",
        local_http=False,
    )


@pytest.fixture
def claims(security_settings: Settings) -> dict[str, Any]:
    now = int(datetime.now(UTC).timestamp())
    return {
        "sub": str(uuid4()),
        "sid": str(uuid4()),
        "jti": str(uuid4()),
        "iss": security_settings.jwt_issuer,
        "aud": security_settings.jwt_audience,
        "type": "access",
        "iat": now,
        "exp": now + 300,
    }


def assert_unauthorized(settings: Settings, token: str) -> None:
    with pytest.raises(ApiError) as error:
        security.decode_access(settings, token)
    assert error.value.status == 401
    assert error.value.code == "unauthorized"
    assert error.value.message == "Authentication required"
    assert error.value.headers == {"WWW-Authenticate": "Bearer"}


def test_access_token_roundtrip_has_bounded_lifetime(security_settings: Settings) -> None:
    user_id, session_id = uuid4(), uuid4()
    token = security.access_token(security_settings, user_id, session_id)
    identity = security.decode_access(security_settings, token)
    payload = jwt.decode(
        token,
        TEST_KEY,
        algorithms=["HS256"],
        issuer=security_settings.jwt_issuer,
        audience=security_settings.jwt_audience,
    )
    assert identity == security.AccessIdentity(user_id, session_id)
    assert payload["exp"] - payload["iat"] == security_settings.access_token_seconds
    assert payload["type"] == "access"
    assert UUID(payload["jti"])
    assert len(token) <= 4096


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b.c", "x" * 4097])
def test_malformed_access_tokens_are_unauthorized(security_settings: Settings, token: str) -> None:
    assert_unauthorized(security_settings, token)


def test_wrong_signature_is_rejected(security_settings: Settings, claims: dict[str, Any]) -> None:
    token = jwt.encode(claims, "different-key-9077aa6d87ba47588c5f314ff8310ff1", "HS256")
    assert_unauthorized(security_settings, token)


@pytest.mark.parametrize("algorithm", ["HS384", "HS512", "none"])
def test_algorithm_confusion_is_rejected(
    security_settings: Settings, claims: dict[str, Any], algorithm: str
) -> None:
    token = jwt.encode(claims, "" if algorithm == "none" else TEST_KEY, algorithm=algorithm)
    assert_unauthorized(security_settings, token)


@pytest.mark.parametrize("missing", ["sub", "sid", "jti", "iss", "aud", "iat", "exp", "type"])
def test_required_claims_cannot_be_omitted(
    security_settings: Settings, claims: dict[str, Any], missing: str
) -> None:
    del claims[missing]
    assert_unauthorized(security_settings, jwt.encode(claims, TEST_KEY, algorithm="HS256"))


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("iss", "another-issuer"),
        ("aud", "another-service"),
        ("type", "refresh"),
        ("type", None),
        ("exp", 1),
        ("exp", "not-a-date"),
        ("iat", 4102444800),
        ("iat", "not-a-date"),
        ("sub", "invalid-uuid"),
        ("jti", "invalid-uuid"),
        ("sid", "invalid-uuid"),
        ("sid", None),
        ("sid", 123),
        ("sid", []),
        ("sid", {}),
    ],
)
def test_invalid_signed_claims_are_unauthorized(
    security_settings: Settings, claims: dict[str, Any], claim: str, value: Any
) -> None:
    claims[claim] = value
    assert_unauthorized(security_settings, jwt.encode(claims, TEST_KEY, algorithm="HS256"))


@pytest.mark.parametrize("length", [0, 14, 129, 10000])
def test_password_hash_rejects_outside_length_limits(length: int) -> None:
    with pytest.raises(ValueError, match="15 to 128"):
        security.hash_password("p" * length)


@pytest.mark.parametrize("password", ["p" * 15, "ż" * 128])
def test_password_hash_is_argon2id_and_verifies(password: str) -> None:
    encoded = security.hash_password(password)
    assert encoded.startswith("$argon2id$v=19$")
    assert security.verify_password(password, encoded)
    assert not security.verify_password(password + "wrong", encoded)


def test_password_hash_uses_independent_salts() -> None:
    password = "unit-test-password-31f0"
    first, second = security.hash_password(password), security.hash_password(password)
    assert first != second
    assert security.verify_password(password, first)
    assert security.verify_password(password, second)


@pytest.mark.parametrize("encoded", ["", "plaintext-password", "$argon2id$broken"])
def test_password_verification_handles_corrupt_stored_hash(encoded: str) -> None:
    assert not security.verify_password("unit-test-password-31f0", encoded)


def test_opaque_tokens_are_urlsafe_unique_and_hash_before_storage() -> None:
    first, second = security.random_token(), security.random_token()
    assert first != second
    assert len(first) >= 43
    assert set(first) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    digest = security.token_hash(first)
    assert len(digest) == 64
    assert set(digest) <= set("0123456789abcdef")
    assert digest == security.token_hash(first)
    assert digest != security.token_hash(second)
    assert first not in digest


def test_csrf_token_is_stable_and_bound_to_session_and_secret(
    security_settings: Settings,
) -> None:
    session_id = uuid4()
    token = security.session_csrf(security_settings, session_id)
    assert token == security.session_csrf(security_settings, session_id)
    assert token != security.session_csrf(security_settings, uuid4())
    other_settings = security_settings.model_copy(
        update={"jwt_secret": SecretStr("different-secret-04c737aac141431eb173ed110410a68d")}
    )
    assert token != security.session_csrf(other_settings, session_id)
    assert len(token) == 64


@pytest.mark.parametrize("attribute", ["event", "component", "http_method"])
@pytest.mark.parametrize("value", [{}, []])
def test_unhashable_logging_extras_cannot_trigger_secret_leaking_fallback(
    attribute: str,
    value: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(logging, "raiseExceptions", True)
    record = logging.LogRecord(
        "httpx", logging.ERROR, __file__, 1, "password=%s", ("private-log-password",), None
    )
    setattr(record, attribute, value)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeJSONFormatter())
    handler.handle(record)
    captured = capsys.readouterr()
    assert "private-log-password" not in captured.err + captured.out + stream.getvalue()
    assert json.loads(stream.getvalue())["event"] == "log_record"
