"""Request/response schemas.

Every *input* schema uses ``extra="forbid"`` and lists only the fields a caller
may set. Privileged fields (``role``, ``is_active``, ``owner_id``, ``id``) never
appear in user-facing input models, which closes off mass assignment
(OWASP API3:2023 / CWE-915).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

InvoiceStatus = Literal["draft", "sent", "paid", "void"]
Role = Literal["user", "admin"]


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------------------------------------------------------------- auth / users
class RegisterRequest(StrictInput):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(StrictInput):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth token type label, not a secret
    expires_in: int


class UserUpdate(StrictInput):
    full_name: str | None = Field(default=None, min_length=1, max_length=120)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    full_name: str
    role: Role
    created_at: datetime


class AdminRoleUpdate(StrictInput):
    role: Role


# ---------------------------------------------------------------- invoices
class InvoiceCreate(StrictInput):
    customer_name: str = Field(min_length=1, max_length=120)
    amount_cents: int = Field(ge=0, le=100_000_000)
    currency: str = Field(default="EUR", pattern=r"^[A-Z]{3}$")
    description: str = Field(default="", max_length=2_000)


class InvoiceUpdate(StrictInput):
    customer_name: str | None = Field(default=None, min_length=1, max_length=120)
    amount_cents: int | None = Field(default=None, ge=0, le=100_000_000)
    description: str | None = Field(default=None, max_length=2_000)
    status: InvoiceStatus | None = None


class InvoiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    customer_name: str
    amount_cents: int
    currency: str
    status: InvoiceStatus
    description: str
    created_at: datetime


# ---------------------------------------------------------------- integrations
class UrlPreviewRequest(StrictInput):
    url: str = Field(min_length=8, max_length=2_048)


class UrlPreviewResponse(BaseModel):
    url: str
    status_code: int
    content_type: str | None
    title: str | None
    redirect_location: str | None = None
