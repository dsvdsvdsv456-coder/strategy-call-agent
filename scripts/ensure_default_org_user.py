"""Ensure the default organization has at least one OWNER user.

The default org (Integrated IT Trainings) exists but has 0 users, which
means no one can authenticate via JWT to initiate Google OAuth.
This script creates an OWNER user so the dashboard login + OAuth flow works.

Usage (inside Docker):
    python /app/scripts/ensure_default_org_user.py

This is idempotent — safe to run multiple times.
"""
import sys
sys.path.insert(0, "/app")

import uuid
from datetime import datetime, timezone

import app.models  # noqa: F401 — register models
import app.models_multi_tenant  # noqa: F401 — register multi-tenant models

from app.database import SessionLocal
from app.models_multi_tenant import Organization, User, UserRole, UserStatus
from app.auth import hash_password

DEFAULT_ORG_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
ADMIN_EMAIL = "admin@integratedittrainings.com"
ADMIN_PASSWORD = "ChangeMe123!"


def main():
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == DEFAULT_ORG_ID).first()
        if not org:
            print(f"FAIL: Default org {DEFAULT_ORG_ID} does not exist!")
            return 1

        print(f"Default org: {org.name} (id={org.id})")

        # Check if user already exists
        existing = db.query(User).filter(
            User.organization_id == DEFAULT_ORG_ID,
            User.email == ADMIN_EMAIL,
        ).first()

        if existing:
            print(f"User already exists: {existing.email} (id={existing.id}, role={existing.role.value})")
            # Ensure password_hash is set
            if not existing.password_hash:
                existing.password_hash = hash_password(ADMIN_PASSWORD)
                db.commit()
                print("  -> Password hash was missing, now set")
            print(f"  -> Status: {existing.status.value}")
            return 0

        # Create the owner user
        password_hash = hash_password(ADMIN_PASSWORD)
        user = User(
            organization_id=DEFAULT_ORG_ID,
            email=ADMIN_EMAIL,
            full_name="Platform Admin",
            password_hash=password_hash,
            role=UserRole.OWNER,
            status=UserStatus.ACTIVE,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        print(f"Created user: {user.email} (id={user.id})")
        print(f"  Role: {user.role.value}")
        print(f"  Status: {user.status.value}")
        print(f"  Org: {org.name}")
        print(f"\nLogin credentials:")
        print(f"  Email:    {ADMIN_EMAIL}")
        print(f"  Password: {ADMIN_PASSWORD}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main() or 0)
