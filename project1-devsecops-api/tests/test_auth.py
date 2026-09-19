"""Broken authentication controls (A07:2021, API2:2023)."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.security import hash_password, verify_password
from tests.conftest import TEST_PASSWORD, login, register


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _claims(settings, sub: str, **overrides) -> dict:
    now = datetime.now(UTC)
    claims = {
        "sub": sub,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=5),
        "jti": "test",
        "typ": "access",
    }
    claims.update(overrides)
    return claims


def test_passwords_are_hashed_with_argon2id():
    hashed = hash_password(TEST_PASSWORD)
    assert hashed.startswith("$argon2id$")
    assert TEST_PASSWORD not in hashed
    assert verify_password(hashed, TEST_PASSWORD)
    assert not verify_password(hashed, TEST_PASSWORD + "x")
    assert not verify_password(None, TEST_PASSWORD)


def test_login_success_returns_short_lived_token(client, settings):
    register(client, "carol@example.com")
    resp = client.post("/auth/login", json={"email": "carol@example.com", "password": TEST_PASSWORD})
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == settings.access_token_ttl_minutes * 60


def test_wrong_password_and_unknown_user_are_indistinguishable(client):
    register(client, "dave@example.com")
    wrong = client.post("/auth/login", json={"email": "dave@example.com", "password": "not-the-password"})
    unknown = client.post("/auth/login", json={"email": "nobody@example.com", "password": "not-the-password"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_weak_password_rejected(client):
    resp = client.post("/auth/register", json={"email": "e@example.com", "full_name": "E", "password": "short"})
    assert resp.status_code == 422


def test_missing_token_rejected(client):
    assert client.get("/users/me").status_code == 401


def test_alg_none_token_rejected(client, settings):
    user = register(client, "frank@example.com")
    claims = _claims(settings, user["id"])
    claims = {k: int(v.timestamp()) if isinstance(v, datetime) else v for k, v in claims.items()}
    unsigned = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(claims)}."
    resp = client.get("/users/me", headers={"Authorization": f"Bearer {unsigned}"})
    assert resp.status_code == 401


def test_token_signed_with_other_key_rejected(client, settings):
    user = register(client, "grace@example.com")
    forged = jwt.encode(
        _claims(settings, user["id"]), "a-completely-different-signing-key-0123456789", algorithm="HS256"
    )
    assert client.get("/users/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_expired_token_rejected(client, settings):
    user = register(client, "heidi@example.com")
    past = datetime.now(UTC) - timedelta(hours=2)
    token = jwt.encode(
        _claims(settings, user["id"], iat=past, nbf=past, exp=past + timedelta(minutes=15)),
        settings.secret_key.get_secret_value(),
        algorithm="HS256",
    )
    assert client.get("/users/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


@pytest.mark.parametrize("claim", ["exp", "aud", "iss", "jti"])
def test_token_missing_required_claim_rejected(client, settings, claim):
    user = register(client, f"ivan-{claim}@example.com")
    claims = _claims(settings, user["id"])
    del claims[claim]
    token = jwt.encode(claims, settings.secret_key.get_secret_value(), algorithm="HS256")
    assert client.get("/users/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_role_claim_in_token_is_not_trusted(client, settings):
    user = register(client, "judy@example.com")
    token = jwt.encode(
        _claims(settings, user["id"], role="admin"), settings.secret_key.get_secret_value(), algorithm="HS256"
    )
    assert client.get("/admin/users", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_valid_token_works(client, alice):
    resp = client.get("/users/me", headers=alice)
    assert resp.status_code == 200
    assert resp.json()["email"] == "alice@example.com"
    assert "password_hash" not in resp.json()


def test_login_is_case_insensitive_on_email(client):
    register(client, "Kate@Example.com")
    assert login(client, "kate@example.com")
