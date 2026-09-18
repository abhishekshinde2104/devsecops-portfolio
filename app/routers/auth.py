from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.logging_config import fingerprint, security_event
from app.metrics import AUTH_EVENTS
from app.models import User
from app.ratelimit import client_ip, enforce
from app.schemas import LoginRequest, RegisterRequest, TokenResponse, UserOut
from app.security import (
    DbDep,
    SettingsDep,
    create_access_token,
    hash_password,
    password_needs_rehash,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, request: Request, settings: SettingsDep, db: DbDep) -> User:
    enforce(request, "register", client_ip(request), settings.login_rate_limit, settings.login_rate_window_seconds)
    # Role is never taken from the request: every self-registered account is a
    # plain user. Admins are created out-of-band (python -m app.cli create-admin).
    user = User(
        email=body.email.lower(),
        full_name=body.full_name,
        password_hash=hash_password(body.password),
        role="user",
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Registration failed") from None
    AUTH_EVENTS.labels(event="registration", reason="ok").inc()
    return user


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, settings: SettingsDep, db: DbDep) -> TokenResponse:
    email = body.email.lower()
    ip = client_ip(request)
    # Two keys: per (IP, account) stops a single attacker hammering one
    # account; per account (4x budget) slows distributed guessing against it.
    enforce(request, "login", f"{ip}|{email}", settings.login_rate_limit, settings.login_rate_window_seconds)
    enforce(request, "login_account", email, settings.login_rate_limit * 4, settings.login_rate_window_seconds)

    user = db.scalar(select(User).where(func.lower(User.email) == email))
    if not verify_password(user.password_hash if user else None, body.password) or user is None:
        AUTH_EVENTS.labels(event="login_failure", reason="bad_credentials").inc()
        security_event("login_failure", account=fingerprint(email), ip=ip)
        # Identical response for unknown user and wrong password (CWE-204).
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        AUTH_EVENTS.labels(event="login_failure", reason="inactive").inc()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
        db.commit()

    AUTH_EVENTS.labels(event="login_success", reason="ok").inc()
    return TokenResponse(
        access_token=create_access_token(settings, user),
        expires_in=settings.access_token_ttl_minutes * 60,
    )
