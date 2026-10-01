"""Configuration rejects incomplete credentials and accidental insecure profiles."""

import os

import pytest
from pydantic import ValidationError

from app.core.config import Settings


@pytest.fixture
def settings_values(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    for name in os.environ:
        if name.startswith("AEGIS_"):
            monkeypatch.delenv(name)
    return {
        "database_url": "postgresql+psycopg://aegis_app:unit-database-key@localhost:5432/aegis",
        "redis_url": "redis://:unit-redis-key@localhost:6379/0",
        "clickhouse_url": "http://localhost:8123",
        "clickhouse_user": "aegis",
        "clickhouse_password": "unit-clickhouse-key",
        "jwt_secret": "test-only-jwt-signing-material-with-32-bytes",
        "public_origin": "https://aegis.example.test",
    }


def test_secure_defaults_and_redacted_secrets(settings_values: dict[str, object]) -> None:
    settings = Settings.model_validate(settings_values)
    assert settings.cookie_secure
    assert settings.refresh_cookie_name.startswith("__Secure-")
    assert settings.preauth_cookie_name.startswith("__Secure-")
    for key in ("database_url", "redis_url", "clickhouse_password", "jwt_secret"):
        assert str(settings_values[key]) not in repr(settings)


@pytest.mark.parametrize(
    "migration",
    [
        {"clickhouse_admin_user": "owner"},
        {"clickhouse_admin_password": "private-owner-secret"},
        {"clickhouse_admin_user": "aegis", "clickhouse_admin_password": "private-owner-secret"},
        {"clickhouse_admin_user": "owner", "clickhouse_admin_password": "CHANGE_ME"},
    ],
)
def test_archive_owner_requires_separate_valid_credentials(
    settings_values: dict[str, object], migration: dict[str, str]
) -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate({**settings_values, **migration})


def test_archive_owner_credentials_are_optional_and_redacted(
    settings_values: dict[str, object],
) -> None:
    runtime = Settings.model_validate(settings_values)
    assert runtime.clickhouse_admin_user is None and runtime.clickhouse_admin_password is None
    owner = Settings.model_validate(
        {
            **settings_values,
            "clickhouse_admin_user": "owner",
            "clickhouse_admin_password": "private-owner-secret",
        }
    )
    assert "private-owner-secret" not in repr(owner)


@pytest.mark.parametrize(
    "field",
    ["database_url", "redis_url", "clickhouse_password", "jwt_secret", "public_origin"],
)
def test_missing_required_settings_fail(settings_values: dict[str, object], field: str) -> None:
    settings_values.pop(field)
    with pytest.raises(ValidationError):
        Settings.model_validate(settings_values)


@pytest.mark.parametrize("field", ["clickhouse_password", "jwt_secret"])
@pytest.mark.parametrize("value", ["", " ", "password", "CHANGE_ME", "<generated>", "replace-me"])
def test_empty_or_placeholder_secrets_fail(
    settings_values: dict[str, object], field: str, value: str
) -> None:
    settings_values[field] = value
    with pytest.raises(ValidationError):
        Settings.model_validate(settings_values)


@pytest.mark.parametrize(
    "url",
    [
        "",
        "not-a-url",
        "sqlite:///local.db",
        "postgresql://user:unit-database-key@localhost/aegis",
        "postgresql+psycopg://localhost/aegis",
        "postgresql+psycopg://user:@localhost/aegis",
        "postgresql+psycopg://user:change_me@localhost/aegis",
        "postgresql+psycopg://user:unit-database-key@localhost/",
    ],
)
def test_database_url_validation(settings_values: dict[str, object], url: str) -> None:
    settings_values["database_url"] = url
    with pytest.raises(ValidationError):
        Settings.model_validate(settings_values)


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://localhost",
        "redis://localhost:6379/0",
        "redis://:@localhost:6379/0",
        "redis://:change_me@localhost:6379/0",
        "redis://:unit-redis-key@localhost:6379/not-a-db",
        "redis://:unit-redis-key@localhost:6379/0#fragment",
        "redis://:unit-redis-key@localhost:invalid/0",
    ],
)
def test_redis_url_validation(settings_values: dict[str, object], url: str) -> None:
    settings_values["redis_url"] = url
    with pytest.raises(ValidationError):
        Settings.model_validate(settings_values)


@pytest.mark.parametrize(
    "url",
    [
        "",
        "tcp://localhost:9000",
        "http://user:secret@localhost:8123",
        "http://localhost:8123/?query=secret",
        "http://localhost:8123/database",
    ],
)
def test_clickhouse_url_is_a_credential_free_origin(
    settings_values: dict[str, object], url: str
) -> None:
    settings_values["clickhouse_url"] = url
    with pytest.raises(ValidationError):
        Settings.model_validate(settings_values)


@pytest.mark.parametrize(
    "origin",
    ["http://localhost:8000", "https://user:password@aegis.test", "https://aegis.test/path", ""],
)
def test_secure_profile_requires_https_origin(
    settings_values: dict[str, object], origin: str
) -> None:
    settings_values["public_origin"] = origin
    with pytest.raises(ValidationError):
        Settings.model_validate(settings_values)


@pytest.mark.parametrize("hostname", ["localhost", "127.0.0.1", "[::1]"])
def test_loopback_http_is_explicit_and_uses_distinct_cookies(
    settings_values: dict[str, object], hostname: str
) -> None:
    settings_values.update(local_http=True, public_origin=f"http://{hostname}:8000/")
    settings = Settings.model_validate(settings_values)
    assert not settings.cookie_secure
    assert settings.refresh_cookie_name == "aegis_local_refresh"
    assert settings.preauth_cookie_name == "aegis_local_preauth"
    assert settings.public_origin == f"http://{hostname}:8000"


@pytest.mark.parametrize(
    "origin", ["http://0.0.0.0:8000", "http://192.168.1.3", "https://localhost"]
)
def test_local_profile_cannot_expose_insecure_cookies_to_a_remote_origin(
    settings_values: dict[str, object], origin: str
) -> None:
    settings_values.update(local_http=True, public_origin=origin)
    with pytest.raises(ValidationError):
        Settings.model_validate(settings_values)


def test_idle_timeout_cannot_exceed_absolute_timeout(settings_values: dict[str, object]) -> None:
    settings_values.update(session_idle_seconds=3600, session_absolute_seconds=600)
    with pytest.raises(ValidationError):
        Settings.model_validate(settings_values)


def test_validation_error_does_not_render_rejected_credentials(
    settings_values: dict[str, object],
) -> None:
    private_value = "private-key-must-not-appear"
    settings_values["jwt_secret"] = private_value
    with pytest.raises(ValidationError) as caught:
        Settings.model_validate(settings_values)
    assert private_value not in str(caught.value)
