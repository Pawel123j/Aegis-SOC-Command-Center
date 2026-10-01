"""Validated process configuration. Importing this module opens no connections."""

from functools import lru_cache
from typing import Self
from urllib.parse import unquote, urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


def _check_secret(value: str, minimum_bytes: int = 1) -> None:
    normalized = value.strip().lower().replace("_", "").replace("-", "").replace(" ", "")
    placeholders = {
        "changeme",
        "replaceme",
        "password",
        "secret",
        "yourpassword",
        "yoursecret",
        "example",
        "placeholder",
        "todo",
        "setme",
        "generatedlocally",
    }
    if (
        len(value.encode("utf-8")) < minimum_bytes
        or not value.strip()
        or normalized in placeholders
        or any(marker in normalized for marker in ("changeme", "replaceme", "placeholder"))
        or "<" in value
        or ">" in value
    ):
        raise ValueError("a nonempty generated secret is required")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_", env_file=None, extra="forbid", hide_input_in_errors=True
    )

    database_url: SecretStr
    redis_url: SecretStr
    clickhouse_url: str
    clickhouse_user: str = Field(min_length=1, max_length=128)
    clickhouse_password: SecretStr
    clickhouse_database: str = Field(default="aegis", pattern=r"^[a-z][a-z0-9_]{0,63}$")
    clickhouse_admin_user: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$")
    clickhouse_admin_password: SecretStr | None = None
    jwt_secret: SecretStr
    jwt_issuer: str = Field(default="aegis-soc", min_length=1)
    jwt_audience: str = Field(default="aegis-api", min_length=1)
    public_origin: str
    local_http: bool = False
    access_token_seconds: int = Field(default=300, ge=60, le=900)
    session_idle_seconds: int = Field(default=43200, ge=300, le=43200)
    session_absolute_seconds: int = Field(default=604800, ge=300, le=604800)
    preauth_seconds: int = Field(default=600, ge=60, le=900)
    ingest_max_stored_events: int = Field(default=100000, ge=1, le=10000000)
    ingest_max_receipt_records: int = Field(default=200000, ge=1, le=20000000)
    ingest_max_stored_bytes: int = Field(default=536870912, ge=1, le=10737418240)
    ingest_max_pending_events: int = Field(default=10000, ge=1, le=1000000)
    ingest_max_oldest_pending_seconds: int = Field(default=300, ge=1, le=86400)
    ingest_dispatch_batch_size: int = Field(default=50, ge=1, le=500)
    ingest_dispatch_lease_seconds: int = Field(default=30, ge=1, le=300)
    ingest_redelivery_seconds: int = Field(default=30, ge=1, le=3600)
    ingest_worker_lease_seconds: int = Field(default=60, ge=31, le=600)
    ingest_max_dispatch_attempts: int = Field(default=10, ge=1, le=100)
    ingest_max_processing_attempts: int = Field(default=5, ge=1, le=20)
    ingest_retry_base_seconds: int = Field(default=2, ge=1, le=60)
    ingest_retry_max_seconds: int = Field(default=60, ge=1, le=3600)
    ingest_relay_poll_seconds: float = Field(default=2.0, ge=0.1, le=60)
    ingest_queue: str = Field(default="ingestion", pattern=r"^[a-zA-Z0-9_.-]{1,64}$")
    pipeline_poll_seconds: float = Field(default=2.0, ge=0.1, le=60)
    pipeline_batch_size: int = Field(default=25, ge=1, le=200)
    pipeline_lease_seconds: int = Field(default=60, ge=31, le=600)
    pipeline_max_normalization_attempts: int = Field(default=3, ge=1, le=20)
    pipeline_max_projection_attempts: int = Field(default=20, ge=1, le=100)
    correlation_poll_seconds: float = Field(default=2.0, ge=0.1, le=60)
    correlation_batch_size: int = Field(default=25, ge=1, le=200)

    @field_validator("jwt_secret")
    @classmethod
    def validate_jwt_secret(cls, value: SecretStr) -> SecretStr:
        _check_secret(value.get_secret_value(), minimum_bytes=32)
        return value

    @field_validator("clickhouse_password")
    @classmethod
    def validate_clickhouse_password(cls, value: SecretStr) -> SecretStr:
        _check_secret(value.get_secret_value())
        return value

    @field_validator("clickhouse_admin_password")
    @classmethod
    def validate_clickhouse_admin_password(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            _check_secret(value.get_secret_value())
        return value

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: SecretStr) -> SecretStr:
        try:
            url = make_url(value.get_secret_value())
            if (
                url.drivername != "postgresql+psycopg"
                or not url.host
                or not url.username
                or not url.database
            ):
                raise ValueError
            _check_secret(url.password or "")
        except (ArgumentError, ValueError, TypeError) as error:
            raise ValueError("a PostgreSQL psycopg URL with credentials is required") from error
        return value

    @field_validator("redis_url")
    @classmethod
    def validate_redis_url(cls, value: SecretStr) -> SecretStr:
        try:
            url = urlsplit(value.get_secret_value())
            if url.scheme not in {"redis", "rediss"} or not url.hostname or url.fragment:
                raise ValueError
            _check_secret(unquote(url.password or ""))
            if url.path and (not url.path.startswith("/") or not url.path[1:].isdigit()):
                raise ValueError
            _ = url.port
        except (ValueError, TypeError) as error:
            raise ValueError("a Redis URL with a generated password is required") from error
        return value

    @field_validator("clickhouse_url")
    @classmethod
    def validate_clickhouse_url(cls, value: str) -> str:
        try:
            url = urlsplit(value)
            if (
                url.scheme not in {"http", "https"}
                or not url.hostname
                or url.username is not None
                or url.password is not None
                or url.query
                or url.fragment
                or url.path not in {"", "/"}
            ):
                raise ValueError
            _ = url.port
        except ValueError as error:
            raise ValueError("a credential-free ClickHouse HTTP(S) origin is required") from error
        return value.rstrip("/")

    @model_validator(mode="after")
    def validate_profile(self) -> Self:
        try:
            origin = urlsplit(self.public_origin)
            if (
                not origin.hostname
                or origin.username is not None
                or origin.password is not None
                or origin.query
                or origin.fragment
                or origin.path not in {"", "/"}
            ):
                raise ValueError
            _ = origin.port
            if self.local_http:
                if origin.scheme != "http" or origin.hostname not in {
                    "localhost",
                    "127.0.0.1",
                    "::1",
                }:
                    raise ValueError
            elif origin.scheme != "https":
                raise ValueError
        except ValueError as error:
            raise ValueError(
                "public_origin requires HTTPS; local_http permits only loopback HTTP"
            ) from error
        if self.session_idle_seconds > self.session_absolute_seconds:
            raise ValueError("session idle timeout cannot exceed the absolute timeout")
        if self.ingest_retry_base_seconds > self.ingest_retry_max_seconds:
            raise ValueError("ingestion retry base cannot exceed the maximum backoff")
        if (self.clickhouse_admin_user is None) != (self.clickhouse_admin_password is None):
            raise ValueError("ClickHouse migration credentials must be supplied together")
        if self.clickhouse_admin_user == self.clickhouse_user:
            raise ValueError("ClickHouse owner and runtime users must be separate")
        self.public_origin = self.public_origin.rstrip("/")
        return self

    @property
    def cookie_secure(self) -> bool:
        return not self.local_http

    @property
    def refresh_cookie_name(self) -> str:
        return "aegis_local_refresh" if self.local_http else "__Secure-aegis_refresh"

    @property
    def preauth_cookie_name(self) -> str:
        return "aegis_local_preauth" if self.local_http else "__Secure-aegis_preauth"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
