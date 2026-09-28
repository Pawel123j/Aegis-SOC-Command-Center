"""Create the first administrator through an operator-only command."""

import argparse
import getpass
import os
import sys
import warnings
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.permissions import Role
from app.core.security import hash_password
from app.infrastructure.database import ADMIN_LOCK_ID, Database
from app.modules.audit.service import append_audit
from app.modules.users.models import User, normalize_username


class BootstrapRefused(ValueError):
    """Bootstrap cannot create an additional administrator."""


def bootstrap_admin(session: Session, username: str, password: str) -> User:
    """Serialize with admin changes; create the identity and its audit atomically."""
    normalized = normalize_username(username)
    encoded = hash_password(password)
    try:
        session.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": ADMIN_LOCK_ID})
        if session.scalar(select(User.id).limit(1)) is not None:
            raise BootstrapRefused("Bootstrap refused: users already exist")
        user = User(username=normalized, password_hash=encoded, role=Role.ADMIN, enabled=True)
        session.add(user)
        session.flush()
        append_audit(
            session,
            action="user.bootstrap",
            outcome="success",
            request_id=str(uuid4()),
            actor_id=user.id,
            object_type="user",
            object_id=str(user.id),
            details={"username": user.username, "role": user.role.value},
        )
        session.commit()
        return user
    except Exception:
        session.rollback()
        raise


def read_password() -> str:
    supplied = os.environ.pop("AEGIS_BOOTSTRAP_PASSWORD", None)
    if supplied is not None:
        return supplied
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        password = getpass.getpass("Administrator password (15–128 characters): ")
        if password != getpass.getpass("Confirm administrator password: "):
            raise ValueError("Passwords do not match")
    return password


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True, help="Username of the first administrator")
    args = parser.parse_args()
    database: Database | None = None
    try:
        username = normalize_username(args.username)
        settings = get_settings()
        password = read_password()
        database = Database(settings)
        with database.session() as session:
            user = bootstrap_admin(session, username, password)
        print(f"Administrator created: {user.username}")
        return 0
    except BootstrapRefused as error:
        print(str(error), file=sys.stderr)
    except (ValueError, SQLAlchemyError):
        # Driver and validation exceptions may carry credentials; do not print them.
        print(
            "Bootstrap failed. Check configuration, migrations, "
            "username and password requirements.",
            file=sys.stderr,
        )
    except (EOFError, KeyboardInterrupt):
        print("Bootstrap cancelled", file=sys.stderr)
    except getpass.GetPassWarning:
        print("A secure terminal or AEGIS_BOOTSTRAP_PASSWORD is required", file=sys.stderr)
    finally:
        if database is not None:
            database.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
