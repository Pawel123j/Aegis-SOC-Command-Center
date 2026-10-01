"""Owner-only checksum-checked ClickHouse migrations; runtime has SELECT/INSERT only."""

import hashlib
from pathlib import Path

from app.core.config import Settings
from app.modules.events.clickhouse import execute, identifier, json_rows

MIGRATIONS = Path(__file__).parent / "modules" / "events" / "migrations"


def migrate(settings: Settings, database: str | None = None) -> None:
    name = identifier(database or settings.clickhouse_database)
    user = identifier(settings.clickhouse_user)
    execute(settings, f"CREATE DATABASE IF NOT EXISTS {name}", owner=True, bounded=False)
    execute(
        settings,
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(version String, checksum FixedString(64), applied_at DateTime64(6, 'UTC')) "
        "ENGINE=ReplacingMergeTree ORDER BY version",
        database=name,
        owner=True,
        bounded=False,
    )
    rows = json_rows(
        execute(
            settings,
            "SELECT version, checksum FROM schema_migrations FINAL FORMAT JSONEachRow",
            database=name,
            owner=True,
        )
    )
    applied = {row["version"]: row["checksum"] for row in rows}
    for path in sorted(MIGRATIONS.glob("[0-9][0-9][0-9][0-9]_*.sql")):
        sql = path.read_bytes()
        checksum = hashlib.sha256(sql).hexdigest()
        version = path.stem
        if version in applied:
            if applied[version] != checksum:
                raise RuntimeError("archive_migration_checksum_mismatch")
            continue
        execute(settings, sql.decode("utf-8"), database=name, owner=True, bounded=False)
        execute(
            settings,
            "INSERT INTO schema_migrations VALUES ({version:String}, {checksum:String}, now64(6))",
            database=name,
            owner=True,
            bounded=False,
            parameters={"param_version": version, "param_checksum": checksum},
        )
    # Hash authentication avoids shipping plaintext runtime secrets in DDL/logs.
    password_hash = hashlib.sha256(
        settings.clickhouse_password.get_secret_value().encode("utf-8")
    ).hexdigest()
    execute(
        settings,
        f"CREATE USER IF NOT EXISTS {user} IDENTIFIED WITH sha256_hash BY '{password_hash}'",
        owner=True,
        bounded=False,
    )
    execute(
        settings,
        f"ALTER USER {user} IDENTIFIED WITH sha256_hash BY '{password_hash}'",
        owner=True,
        bounded=False,
    )
    execute(settings, f"GRANT SELECT, INSERT ON {name}.events TO {user}", owner=True, bounded=False)


def main() -> None:
    try:
        migrate(Settings())
    except Exception:
        raise SystemExit(
            "ClickHouse migration failed; credentials and server details omitted"
        ) from None


if __name__ == "__main__":
    main()
