"""Create local Compose secrets without printing them or overwriting existing data."""

from __future__ import annotations

import argparse
import os
import secrets
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".env"))
    args = parser.parse_args()
    values = {
        "POSTGRES_OWNER_PASSWORD": secrets.token_urlsafe(48),
        "POSTGRES_APP_PASSWORD": secrets.token_urlsafe(48),
        "REDIS_PASSWORD": secrets.token_urlsafe(48),
        "CLICKHOUSE_PASSWORD": secrets.token_urlsafe(48),
        "AEGIS_JWT_SECRET": secrets.token_urlsafe(64),
        "AEGIS_PUBLIC_ORIGIN": "http://localhost:8080",
        "AEGIS_LOCAL_HTTP": "true",
    }
    try:
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        parser.exit(1, "Existing configuration preserved; choose a new --output path.\n")
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write("# Generated local-only configuration; do not commit.\n")
        stream.writelines(f"{key}={value}\n" for key, value in values.items())
    print("Created local configuration; secret values were not printed.")


if __name__ == "__main__":
    main()
