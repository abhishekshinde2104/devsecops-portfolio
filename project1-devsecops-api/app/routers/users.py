from __future__ import annotations

from fastapi import APIRouter

from app.models import User
from app.schemas import UserOut, UserUpdate
from app.security import CurrentUser, DbDep

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserOut)
def read_me(user: CurrentUser) -> User:
    return user


@router.patch("/me", response_model=UserOut)
def update_me(body: UserUpdate, user: CurrentUser, db: DbDep) -> User:
    # Explicit field-by-field copy from an allowlisted schema. Unknown fields
    # such as "role" or "is_active" are rejected with 422 by the schema.
    if body.full_name is not None:
        user.full_name = body.full_name
    db.commit()
    return user
