"""Rate limiting (API4:2023), secret handling, headers and error handling."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.main import create_app
from app.ratelimit import RateLimiter
from tests.conftest import register

# ------------------------------------------------------------ rate limiting


def test_login_brute_force_is_throttled(client, settings):
    register(client, "target@example.com")
    codes = [
        client.post("/auth/login", json={"email": "target@example.com", "password": f"guess-{i}"}).status_code
        for i in range(settings.login_rate_limit + 2)
    ]
    assert codes[: settings.login_rate_limit] == [401] * settings.login_rate_limit
    assert codes[-1] == 429


def test_throttled_response_has_retry_after(client, settings):
    for i in range(settings.login_rate_limit + 1):
        resp = client.post("/auth/login", json={"email": "x@example.com", "password": f"p{i}"})
    assert resp.status_code == 429
    assert int(resp.headers["Retry-After"]) >= 1
    assert "rate_limit_rejections_total" in client.get("/metrics").text


def test_global_rate_limit(settings):
    tight = settings.model_copy(update={"global_rate_limit": 3})
    with TestClient(create_app(tight)) as c:
        codes = [c.get("/users/me").status_code for _ in range(4)]
    assert codes == [401, 401, 401, 429]


def test_sliding_window_recovers():
    now = [0.0]
    limiter = RateLimiter(clock=lambda: now[0])
    assert all(limiter.hit("k", 2, 10).allowed for _ in range(2))
    assert not limiter.hit("k", 2, 10).allowed
    now[0] = 10.5
    assert limiter.hit("k", 2, 10).allowed


def test_limiter_memory_is_bounded():
    limiter = RateLimiter(max_keys=100)
    for i in range(1_000):
        limiter.hit(f"k{i}", 5, 60)
    assert len(limiter._hits) <= 100


# ------------------------------------------------------------ secrets / config


@pytest.mark.parametrize("value", ["changeme", "short", "x" * 31, "change-me"])
def test_weak_or_placeholder_secret_refused(value):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, secret_key=value)


def test_missing_secret_refused(monkeypatch):
    monkeypatch.delenv("APP_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_secret_not_exposed_in_repr(settings):
    assert settings.secret_key.get_secret_value() not in repr(settings)


# ------------------------------------------------------------ headers / errors


def test_security_headers_present(client):
    resp = client.get("/healthz")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["Cache-Control"] == "no-store"


def test_request_id_sanitised(client):
    assert client.get("/healthz", headers={"X-Request-ID": "abc-123"}).headers["X-Request-ID"] == "abc-123"
    injected = client.get("/healthz", headers={"X-Request-ID": "bad value<script>"}).headers["X-Request-ID"]
    assert injected != "bad value<script>" and len(injected) == 32


def test_docs_disabled_by_default(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_unhandled_errors_do_not_leak_details(settings):
    app = create_app(settings)

    @app.get("/boom")
    def boom():
        raise RuntimeError("database password is hunter2")

    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.get("/boom")
    assert resp.status_code == 500
    assert resp.json() == {"detail": "Internal server error"}
    assert "hunter2" not in resp.text


def test_metrics_use_route_templates_not_raw_paths(client, alice):
    client.get("/invoices/some-random-id-123", headers=alice)
    text = client.get("/metrics").text
    assert 'route="/invoices/{invoice_id}"' in text
    assert "some-random-id-123" not in text


# ------------------------------------------------------------ admin bootstrap CLI


def test_cli_creates_admin_from_env(tmp_path, monkeypatch):
    import secrets

    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    from app import cli
    from app.config import get_settings
    from app.models import User

    db_url = f"sqlite:///{tmp_path / 'cli.db'}"
    monkeypatch.setenv("APP_SECRET_KEY", secrets.token_urlsafe(48))
    monkeypatch.setenv("APP_DATABASE_URL", db_url)
    monkeypatch.setenv("APP_ADMIN_PASSWORD", secrets.token_urlsafe(16))
    get_settings.cache_clear()
    try:
        assert cli.main(["create-admin", "--email", "Ops@Example.com"]) == 0
        assert cli.main(["create-admin", "--email", "ops@example.com"]) == 0  # idempotent
        monkeypatch.setenv("APP_ADMIN_PASSWORD", "short")
        assert cli.main(["create-admin", "--email", "weak@example.com"]) == 1
    finally:
        get_settings.cache_clear()

    with Session(create_engine(db_url)) as db:
        users = db.scalars(select(User)).all()
    assert [(u.email, u.role) for u in users] == [("ops@example.com", "admin")]


def test_secret_key_can_be_read_from_mounted_secrets_dir(tmp_path, monkeypatch):
    import secrets as pysecrets

    from app.config import get_settings

    value = pysecrets.token_urlsafe(48)
    (tmp_path / "APP_SECRET_KEY").write_text(value)
    monkeypatch.delenv("APP_SECRET_KEY", raising=False)
    monkeypatch.setenv("APP_SECRETS_DIR", str(tmp_path))
    get_settings.cache_clear()
    try:
        assert get_settings().secret_key.get_secret_value() == value
    finally:
        get_settings.cache_clear()
