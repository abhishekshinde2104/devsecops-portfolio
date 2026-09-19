"""Application settings.

All secrets come from the environment (or a local, git-ignored ``.env`` file).
There are no default secrets: the app refuses to start if ``APP_SECRET_KEY`` is
missing, too short, or a known placeholder value.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PLACEHOLDER_SECRETS = {
    "changeme",
    "change-me",
    "secret",
    "your-secret-key",
    "replace-me",
}
MIN_SECRET_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="APP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Literal["dev", "test", "prod"] = "prod"

    # --- Authentication -------------------------------------------------
    secret_key: SecretStr
    jwt_issuer: str = "secure-invoice-api"
    jwt_audience: str = "secure-invoice-api-clients"
    access_token_ttl_minutes: int = Field(default=15, ge=1, le=60)

    # --- Persistence ----------------------------------------------------
    database_url: str = "sqlite:///./app.db"

    # --- Rate limiting (requests per window) -----------------------------
    global_rate_limit: int = Field(default=120, ge=1)
    global_rate_window_seconds: int = Field(default=60, ge=1)
    login_rate_limit: int = Field(default=5, ge=1)
    login_rate_window_seconds: int = Field(default=60, ge=1)
    outbound_rate_limit: int = Field(default=10, ge=1)
    outbound_rate_window_seconds: int = Field(default=60, ge=1)

    # --- Outbound HTTP (SSRF controls) -----------------------------------
    outbound_allowed_hosts: list[str] = Field(default_factory=list)
    outbound_allow_http: bool = False
    outbound_allowed_ports: list[int] = Field(default_factory=lambda: [443])
    outbound_timeout_seconds: float = Field(default=3.0, gt=0, le=10)
    outbound_max_bytes: int = Field(default=512_000, ge=1_024, le=5_000_000)

    # --- Surface area ---------------------------------------------------
    docs_enabled: bool = False
    metrics_enabled: bool = True

    @field_validator("secret_key")
    @classmethod
    def _secret_must_be_strong(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if raw.strip().lower() in _PLACEHOLDER_SECRETS:
            raise ValueError("APP_SECRET_KEY is a placeholder value; generate a real one")
        if len(raw) < MIN_SECRET_LENGTH:
            raise ValueError(f"APP_SECRET_KEY must be at least {MIN_SECRET_LENGTH} characters")
        return value

    @field_validator("outbound_allowed_hosts")
    @classmethod
    def _normalise_hosts(cls, hosts: list[str]) -> list[str]:
        return [h.strip().rstrip(".").lower() for h in hosts if h.strip()]


@lru_cache
def get_settings() -> Settings:
    # APP_SECRETS_DIR points at a directory of files named after the settings
    # (e.g. /run/secrets/app/APP_SECRET_KEY). In Kubernetes the Secret is
    # mounted there as files instead of env vars (CIS 5.4.1): env vars leak
    # into /proc/<pid>/environ, crash dumps and `kubectl describe` output.
    # Environment variables still take precedence when both are set.
    return Settings(_secrets_dir=os.environ.get("APP_SECRETS_DIR") or None)  # type: ignore[call-arg]
