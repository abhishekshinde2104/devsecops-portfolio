from __future__ import annotations

import secrets
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

TEST_PASSWORD = secrets.token_urlsafe(18)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        env="test",
        secret_key=secrets.token_urlsafe(48),
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        global_rate_limit=10_000,
        login_rate_limit=5,
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as c:
        yield c


def register(client: TestClient, email: str, password: str = TEST_PASSWORD, **extra) -> dict:
    resp = client.post("/auth/register", json={"email": email, "full_name": "Test User", "password": password, **extra})
    assert resp.status_code == 201, resp.text
    return resp.json()


def login(client: TestClient, email: str, password: str = TEST_PASSWORD) -> dict[str, str]:
    resp = client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


@pytest.fixture
def alice(client: TestClient) -> dict[str, str]:
    register(client, "alice@example.com")
    return login(client, "alice@example.com")


@pytest.fixture
def bob(client: TestClient) -> dict[str, str]:
    register(client, "bob@example.com")
    return login(client, "bob@example.com")


@pytest.fixture
def make_admin(client: TestClient):
    def _promote(email: str) -> None:
        from sqlalchemy import select

        from app.models import User

        with client.app.state.session_factory() as db:
            user = db.scalar(select(User).where(User.email == email))
            user.role = "admin"
            db.commit()

    return _promote
