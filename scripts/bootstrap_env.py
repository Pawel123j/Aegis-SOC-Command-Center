"""Create local Compose secrets without printing them or overwriting existing data."""

from __future__ import annotations

import argparse
import os
import secrets
import tempfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".env"))
    parser.add_argument(
        "--upgrade", action="store_true", help="Add new keys, preserving existing secrets"
    )
    args = parser.parse_args()
    values = {
        "POSTGRES_OWNER_PASSWORD": secrets.token_urlsafe(48),
        "POSTGRES_APP_PASSWORD": secrets.token_urlsafe(48),
        "REDIS_PASSWORD": secrets.token_urlsafe(48),
        "CLICKHOUSE_PASSWORD": secrets.token_urlsafe(48),
        "CLICKHOUSE_OWNER_PASSWORD": secrets.token_urlsafe(48),
        "AEGIS_JWT_SECRET": secrets.token_urlsafe(64),
        "AEGIS_PUBLIC_ORIGIN": "http://localhost:8080",
        "AEGIS_LOCAL_HTTP": "true",
    }
    if args.upgrade and args.output.exists():
        original = args.output.read_bytes()
        content = original.decode("utf-8")
        keys = {line.split("=", 1)[0].strip() for line in content.splitlines() if "=" in line}
        # Previous release's credentials belong to existing persistent volumes.
        # Only the newly introduced migration-owner credential may be added.
        if "CLICKHOUSE_OWNER_PASSWORD" in keys:
            print("Existing configuration preserved; no new keys required.")
            return
        required = set(values) - {"CLICKHOUSE_OWNER_PASSWORD"}
        if not required <= keys:
            parser.exit(1, "Incomplete existing configuration preserved; check .env.example.\n")
        addition = f"CLICKHOUSE_OWNER_PASSWORD={values['CLICKHOUSE_OWNER_PASSWORD']}\n".encode()
        with tempfile.NamedTemporaryFile(dir=args.output.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(
                original + (b"\n" if original and not original.endswith(b"\n") else b"") + addition
            )
            stream.flush()
            os.fsync(stream.fileno())
        try:
            temporary.chmod(args.output.stat().st_mode)
            if args.output.read_bytes() != original:
                parser.exit(1, "Configuration changed concurrently; upgrade cancelled.\n")
            os.replace(temporary, args.output)
        finally:
            temporary.unlink(missing_ok=True)
        print("Added migration-owner configuration; existing secret values preserved.")
        return
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
