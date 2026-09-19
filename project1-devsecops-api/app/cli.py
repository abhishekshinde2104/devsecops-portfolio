"""Out-of-band admin bootstrap.

    python -m app.cli create-admin --email admin@example.com

The password is read from the APP_ADMIN_PASSWORD environment variable or an
interactive prompt, never from argv (argv is visible in `ps` and shell history).
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import select

from app.config import get_settings
from app.db import Base, build_engine, build_session_factory
from app.models import User
from app.security import hash_password


def create_admin(email: str, full_name: str) -> int:
    password = os.environ.get("APP_ADMIN_PASSWORD") or getpass.getpass("Admin password: ")
    if len(password) < 12:
        print("password must be at least 12 characters", file=sys.stderr)
        return 1
    settings = get_settings()
    engine = build_engine(settings.database_url)
    Base.metadata.create_all(engine)
    with build_session_factory(engine)() as db:
        user = db.scalar(select(User).where(User.email == email.lower()))
        if user is None:
            user = User(email=email.lower(), full_name=full_name, password_hash=hash_password(password))
            db.add(user)
        user.role = "admin"
        db.commit()
    print(f"admin ready: {email.lower()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    admin = sub.add_parser("create-admin", help="create or promote an admin account")
    admin.add_argument("--email", required=True)
    admin.add_argument("--full-name", default="Administrator")
    args = parser.parse_args(argv)
    return create_admin(args.email, args.full_name)


if __name__ == "__main__":
    raise SystemExit(main())
