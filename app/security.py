"""Password hashing, JWT issuance/validation and auth dependencies.

Controls (OWASP A07:2021, API2:2023):
* Argon2id password hashing with per-hash salt (argon2-cffi defaults).
* JWTs signed with HS256 using a key from the environment; the accepted
  algorithm list is pinned, so ``alg: none`` or algorithm-confusion tokens fail.
* ``exp``/``iat``/``nbf``/``iss``/``aud``/``sub``/``jti`` are all required.
* The user's role is re-read from the database on every request; a role claim
  inside the token is informational only and never trusted for authorization.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import Settings
from app.db import get_db
from app.logging_config import security_event
from app.metrics import AUTH_EVENTS, AUTHZ_DENIED
from app.models import User

JWT_ALGORITHM = "HS256"
_REQUIRED_CLAIMS = ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]

_hasher = PasswordHasher()
# Verifying against a dummy hash when the user does not exist keeps response
# times similar for known and unknown e-mail addresses (CWE-204).
_DUMMY_HASH = _hasher.hash(uuid.uuid4().hex)

_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def create_access_token(settings: Settings, user: User) -> str:
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "sub": user.id,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=settings.access_token_ttl_minutes),
        "jti": uuid.uuid4().hex,
        "typ": "access",
    }
    return jwt.encode(claims, settings.secret_key.get_secret_value(), algorithm=JWT_ALGORITHM)


def decode_access_token(settings: Settings, token: str) -> dict[str, Any]:
    claims = jwt.decode(
        token,
        settings.secret_key.get_secret_value(),
        algorithms=[JWT_ALGORITHM],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        options={"require": _REQUIRED_CLAIMS},
        leeway=10,
    )
    if claims.get("typ") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return claims


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
DbDep = Annotated[Session, Depends(get_db)]


def get_current_user(
    request: Request,
    settings: SettingsDep,
    db: DbDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()
    try:
        claims = decode_access_token(settings, credentials.credentials)
    except jwt.ExpiredSignatureError:
        AUTH_EVENTS.labels(event="token_rejected", reason="expired").inc()
        raise _unauthorized() from None
    except jwt.PyJWTError:
        AUTH_EVENTS.labels(event="token_rejected", reason="invalid").inc()
        security_event("token_rejected", reason="invalid", path=request.url.path)
        raise _unauthorized() from None

    user = db.get(User, claims["sub"])
    if user is None or not user.is_active:
        AUTH_EVENTS.labels(event="token_rejected", reason="unknown_or_inactive_user").inc()
        raise _unauthorized()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_admin(request: Request, user: CurrentUser) -> User:
    if user.role != "admin":
        AUTHZ_DENIED.labels(resource="admin", reason="missing_role").inc()
        security_event("admin_access_denied", user_id=user.id, path=request.url.path)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return user


AdminUser = Annotated[User, Depends(require_admin)]
