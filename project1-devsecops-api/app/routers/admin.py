"""Admin endpoints (OWASP API5:2023 Broken Function Level Authorization).

The whole router depends on ``require_admin``, so a new endpoint added here
cannot accidentally ship without the role check.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select

from app.logging_config import security_event
from app.models import User
from app.schemas import AdminRoleUpdate, UserOut
from app.security import AdminUser, DbDep, require_admin

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])


@router.get("/users", response_model=list[UserOut])
def list_users(
    db: DbDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[User]:
    return list(db.scalars(select(User).order_by(User.created_at).limit(limit).offset(offset)))


@router.patch("/users/{user_id}/role", response_model=UserOut)
def set_role(user_id: str, body: AdminRoleUpdate, admin: AdminUser, db: DbDep) -> User:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.id == admin.id and body.role != "admin":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Admins cannot demote themselves")
    target.role = body.role
    db.commit()
    security_event("role_changed", actor=admin.id, target=target.id, role=body.role)
    return target
