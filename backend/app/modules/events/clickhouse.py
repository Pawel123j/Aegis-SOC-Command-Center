"""Authenticated, bounded HTTP archive access. Runtime credentials execute no DDL."""

import json
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx

from app.core.config import Settings
from app.modules.events.query import compile_query, parse_query
from app.modules.events.schemas import SearchRequest
from app.modules.ingestion.schemas import canonical_json
from app.modules.normalization.schemas import NormalizedSecurityEvent

IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
MAX_RESPONSE_BYTES = 52428800
QUERY_LIMITS = {
    "max_execution_time": "3",
    "max_memory_usage": "268435456",
    "max_rows_to_read": "1000000",
    "max_bytes_to_read": "268435456",
    "max_result_rows": "501",
    "max_result_bytes": str(MAX_RESPONSE_BYTES),
    "result_overflow_mode": "throw",
    "read_overflow_mode": "throw",
    "timeout_overflow_mode": "throw",
    "wait_end_of_query": "1",
}


class ClickHouseUnavailable(RuntimeError):
    """Never retains a server error body, SQL, input data or credentials."""


def identifier(value: str) -> str:
    if not IDENTIFIER.fullmatch(value):
        raise ValueError("invalid archive identifier")
    return value


def escaped_parameter(value: str) -> str:
    # HTTP param_* values use ClickHouse escaped format after URL decoding.
    # Escaping backslashes also keeps a literal \\N from turning into null.
    return value.translate({92: r"\\", 9: r"\t", 10: r"\n", 13: r"\r", 8: r"\b", 12: r"\f"})


def execute(
    settings: Settings,
    sql: str,
    *,
    database: str | None = None,
    parameters: dict[str, str] | None = None,
    owner: bool = False,
    bounded: bool = True,
) -> str:
    if owner:
        if settings.clickhouse_admin_user is None or settings.clickhouse_admin_password is None:
            raise ValueError("ClickHouse migration credentials are required")
        user = settings.clickhouse_admin_user
        password = settings.clickhouse_admin_password.get_secret_value()
    else:
        user = settings.clickhouse_user
        password = settings.clickhouse_password.get_secret_value()
    params = dict(QUERY_LIMITS) if bounded else {"wait_end_of_query": "1"}
    if database is not None:
        params["database"] = identifier(database)
    params.update(
        {
            key: escaped_parameter(value) if key.startswith("param_") else value
            for key, value in (parameters or {}).items()
        }
    )
    try:
        with httpx.Client(
            auth=(user, password),
            timeout=httpx.Timeout(10, connect=2),
            trust_env=False,
            follow_redirects=False,
        ) as client:
            with client.stream(
                "POST",
                settings.clickhouse_url,
                params=params,
                content=sql.encode("utf-8"),
                headers={"Content-Type": "text/plain; charset=utf-8"},
            ) as response:
                if response.status_code != 200:
                    raise ClickHouseUnavailable("archive_unavailable")
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > MAX_RESPONSE_BYTES:
                        raise ClickHouseUnavailable("archive_unavailable")
                return content.decode("utf-8")
    except (httpx.HTTPError, UnicodeError):
        raise ClickHouseUnavailable("archive_unavailable") from None


def json_rows(text: str) -> list[dict[str, Any]]:
    try:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        if any(not isinstance(row, dict) for row in rows):
            raise ValueError
        return rows
    except (ValueError, TypeError):
        raise ClickHouseUnavailable("archive_unavailable") from None


def archive_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")


class ClickHouseEvents:
    def __init__(self, settings: Settings, database: str | None = None) -> None:
        self.settings = settings
        self.database = identifier(database or settings.clickhouse_database)

    def insert(self, document: dict[str, Any]) -> None:
        event = NormalizedSecurityEvent.model_validate(document)
        stored = event.model_dump(mode="json")
        row: dict[str, object] = {
            "event_id": str(event.event_id),
            "source_id": str(event.source_id),
            "dataset_id": str(event.dataset_id),
            "run_id": str(event.run_id),
            "timestamp": archive_time(event.timestamp),
            "mode": event.mode,
            "document": canonical_json(stored).decode("utf-8"),
            "projection_version": 1,
        }
        for section, names in {
            "source": ("name", "type", "ip", "port"),
            "destination": ("ip", "port"),
            "user": ("id", "name", "realm"),
            "host": ("id", "name"),
            "process": ("name", "executable", "command_line"),
            "event": ("category", "type", "action", "outcome", "severity", "code"),
            "network": ("protocol",),
            "http": ("status_code",),
        }.items():
            for name in names:
                column = "command_line" if name == "command_line" else f"{section}_{name}"
                value = stored.get(section) or {}
                row[column] = value.get(name)
        target = stored["user"]["target"]
        for name in ("id", "name", "realm"):
            row[f"user_target_{name}"] = target.get(name)
        execute(
            self.settings,
            "INSERT INTO events FORMAT JSONEachRow\n" + canonical_json(row).decode("utf-8"),
            database=self.database,
            bounded=False,
        )

    def search(
        self,
        request: SearchRequest,
        start: datetime,
        end: datetime,
        after: tuple[datetime, UUID] | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        expression, params = compile_query(parse_query(request.q))
        params.update({"param_start": archive_time(start), "param_end": archive_time(end)})
        filters = [
            "timestamp >= {start:DateTime64(6, 'UTC')}",
            "timestamp < {end:DateTime64(6, 'UTC')}",
            f"({expression})",
        ]
        for name in ("mode", "dataset_id", "source_id", "run_id"):
            value = getattr(request, name)
            if value is not None:
                params[f"param_{name}"] = str(value)
                kind = "String" if name == "mode" else "UUID"
                filters.append(name + " = {" + name + ":" + kind + "}")
        # Disable PREWHERE optimization so filters cannot remove a newer replacement
        # before FINAL deduplicates immutable event keys.
        source = "(SELECT * FROM events FINAL SETTINGS optimize_move_to_prewhere=0)"
        where = " AND ".join(filters)
        counts = json_rows(
            execute(
                self.settings,
                f"SELECT count() AS total FROM {source} WHERE {where} FORMAT JSONEachRow",
                database=self.database,
                parameters=params,
            )
        )
        try:
            total = int(counts[0]["total"])
            if total < 0:
                raise ValueError
        except (IndexError, KeyError, TypeError, ValueError):
            raise ClickHouseUnavailable("archive_unavailable") from None
        if after is not None:
            params["param_after_time"] = archive_time(after[0])
            params["param_after_id"] = str(after[1])
            where += (
                " AND (timestamp, toString(event_id)) < "
                "({after_time:DateTime64(6, 'UTC')}, {after_id:String})"
            )
        params["param_limit"] = str(request.limit + 1)
        rows = json_rows(
            execute(
                self.settings,
                f"SELECT document FROM {source} WHERE {where} "
                "ORDER BY timestamp DESC, toString(event_id) DESC "
                "LIMIT {limit:UInt32} FORMAT JSONEachRow",
                database=self.database,
                parameters=params,
            )
        )
        try:
            documents = [
                NormalizedSecurityEvent.model_validate_json(row["document"]).model_dump(mode="json")
                for row in rows
            ]
        except (ValueError, KeyError, TypeError):
            raise ClickHouseUnavailable("archive_unavailable") from None
        return documents, total

    def get_event(self, event_id: UUID) -> dict[str, Any] | None:
        rows = json_rows(
            execute(
                self.settings,
                "SELECT document FROM (SELECT * FROM events FINAL "
                "SETTINGS optimize_move_to_prewhere=0) "
                "WHERE event_id={id:UUID} LIMIT 1 FORMAT JSONEachRow",
                database=self.database,
                parameters={"param_id": str(event_id)},
            )
        )
        if not rows:
            return None
        try:
            return NormalizedSecurityEvent.model_validate_json(rows[0]["document"]).model_dump(
                mode="json"
            )
        except (ValueError, KeyError, TypeError):
            raise ClickHouseUnavailable("archive_unavailable") from None
