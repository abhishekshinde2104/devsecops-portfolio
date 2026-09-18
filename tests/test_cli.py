"""Out-of-band admin bootstrap (the only way to obtain the admin role)."""

from __future__ import annotations

import secrets

import pytest
from sqlalchemy import select

from app import cli
from app.config import get_settings
from app.db import build_engine, build_session_factory
from app.models import User


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'cli.db'}"
    monkeypatch.setenv("APP_SECRET_KEY", secrets.token_urlsafe(48))
    monkeypatch.setenv("APP_DATABASE_URL", db_url)
    get_settings.cache_clear()
    yield db_url
    get_settings.cache_clear()


def _role(db_url: str, email: str) -> str | None:
    with build_session_factory(build_engine(db_url))() as db:
        user = db.scalar(select(User).where(User.email == email))
        return user.role if user else None


def test_create_admin_reads_password_from_env(cli_env, monkeypatch):
    monkeypatch.setenv("APP_ADMIN_PASSWORD", secrets.token_urlsafe(16))
    assert cli.main(["create-admin", "--email", "Ops@Example.com"]) == 0
    assert _role(cli_env, "ops@example.com") == "admin"
    # idempotent: running again promotes/keeps the same account
    assert cli.main(["create-admin", "--email", "ops@example.com"]) == 0


def test_create_admin_rejects_short_password(cli_env, monkeypatch):
    monkeypatch.setenv("APP_ADMIN_PASSWORD", "short")
    assert cli.main(["create-admin", "--email", "ops@example.com"]) == 1
    assert _role(cli_env, "ops@example.com") is None
