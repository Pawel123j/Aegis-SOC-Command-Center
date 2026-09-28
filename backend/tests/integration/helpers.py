"""Test-only clients and migration utilities for isolated databases."""

from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from app.core.config import Settings
from app.core.security import random_token
from app.main import create_app

BACKEND = Path(__file__).resolve().parents[2]


def migrate(engine: Engine, revision: str = "head", *, downgrade: bool = False) -> None:
    config = Config(str(BACKEND / "alembic.ini"))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        if downgrade:
            command.downgrade(config, revision)
        else:
            command.upgrade(config, revision)


@dataclass(repr=False)
class IsolatedDatabase:
    name: str
    owner: Engine
    runtime: Engine
    settings: Settings


@dataclass(repr=False)
class Login:
    client: TestClient
    access: str
    csrf: str
    user_id: str
    password: str

    @property
    def authorization(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access}"}

    @property
    def mutation_headers(self) -> dict[str, str]:
        return {
            "Origin": str(self.client.base_url).rstrip("/"),
            "X-CSRF-Token": self.csrf,
        }


@dataclass(repr=False)
class Case:
    database: IsolatedDatabase
    stack: ExitStack = field(default_factory=ExitStack)

    def client(self, settings: Settings | None = None) -> TestClient:
        configuration = settings or self.database.settings
        return self.stack.enter_context(
            TestClient(
                create_app(configuration),
                base_url=configuration.public_origin,
                client=(f"aegis-test-{uuid4().hex}", 50000),
            )
        )

    def login(self, username: str, password: str) -> Login:
        client = self.client()
        csrf = client.get("/api/v1/auth/csrf")
        assert csrf.status_code == 200
        response = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
            headers={
                "Origin": self.database.settings.public_origin,
                "X-CSRF-Token": csrf.json()["csrf_token"],
            },
        )
        assert response.status_code == 200
        tokens = response.json()
        identity = client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        assert identity.status_code == 200
        return Login(
            client, tokens["access_token"], tokens["csrf_token"], identity.json()["id"], password
        )

    def create_user(self, admin: Login, role: str = "soc_analyst") -> dict[str, object]:
        password = random_token()
        response = admin.client.post(
            "/api/v1/users",
            json={"username": f"user_{uuid4().hex}", "password": password, "role": role},
            headers=admin.authorization,
        )
        assert response.status_code == 201
        assert response.headers["etag"] == '"1"'
        return {**response.json(), "password": password}
