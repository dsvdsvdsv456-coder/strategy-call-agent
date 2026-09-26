"""Invitation code service for invite-only account creation.

Manages the lifecycle of one-time invitation codes:
  - Generation (cryptographically secure)
  - Validation (before registration)
  - Redemption (atomic consumption during registration)
  - Listing and revocation (admin operations)

SECURITY:
  - Codes are generated with secrets.token_urlsafe for cryptographic randomness.
  - Codes are stored as bcrypt hashes — plaintext NEVER persisted.
  - Each code is single-use (atomic redemption prevents double-consume).
  - Code comparison uses constant-time bcrypt verification.
  - Plaintext code is ONLY returned to the creator at generation time.
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.auth import hash_password, verify_password
from app.models_multi_tenant import (
    InvitationCode,
    InvitationStatus,
    User,
    UserRole,
)

logger = logging.getLogger(__name__)

# ── Code generation constants ────────────────────────────────────────────────

_CODE_PREFIX = "SCA"
_CODE_SEGMENT_LENGTH = 4  # chars per segment
_CODE_SEGMENTS = 2        # number of random segments (e.g. SCA-XXXX-XXXX)


class InvitationError(Exception):
    """Base exception for invitation errors."""

    def __init__(self, message: str, error_code: str = "invitation_error"):
        super().__init__(message)
        self.error_code = error_code


class InvitationNotFoundError(InvitationError):
    """Raised when an invitation code is not found."""

    def __init__(self, message: str = "Invalid invitation code."):
        super().__init__(message, error_code="invitation_not_found")


class InvitationExpiredError(InvitationError):
    """Raised when an invitation code has expired."""

    def __init__(self):
        super().__init__(
            "This invitation code has expired.",
            error_code="invitation_expired",
        )


class InvitationAlreadyUsedError(InvitationError):
    """Raised when an invitation code has already been redeemed."""

    def __init__(self):
        super().__init__(
            "This invitation code has already been used.",
            error_code="invitation_already_used",
        )


class InvitationRevokedError(InvitationError):
    """Raised when an invitation code has been revoked."""

    def __init__(self):
        super().__init__(
            "This invitation code has been revoked.",
            error_code="invitation_revoked",
        )


# ── Code Generation ──────────────────────────────────────────────────────────


def generate_invitation_code() -> str:
    """Generate a cryptographically secure random invitation code.

    Format: SCA-XXXX-XXXX where X is alphanumeric (uppercase + digits).

    Returns:
        The plaintext code (shown once to creator, never stored).
    """
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I/O/0/1 to avoid confusion
    segments = []
    for _ in range(_CODE_SEGMENTS):
        seg = "".join(secrets.choice(alphabet) for _ in range(_CODE_SEGMENT_LENGTH))
        segments.append(seg)
    return f"{_CODE_PREFIX}-{'-'.join(segments)}"


def _get_code_prefix(code: str) -> str:
    """Extract the first segment for display (e.g. 'SCA-7XK9' from 'SCA-7XK9-PQ42')."""
    parts = code.split("-")
    if len(parts) >= 2:
        return "-".join(parts[:2])
    return code[:10]


# ── Invitation CRUD ──────────────────────────────────────────────────────────


def create_invitation(
    db: Session,
    *,
    created_by_user_id: Any,
    organization_id: Any,
    label: str | None = None,
    email: str | None = None,
    expires_in_days: int | None = None,
) -> dict[str, Any]:
    """Create a new invitation code.

    Returns a dict with the plaintext code and metadata.
    The plaintext code is ONLY returned here — it's never stored.

    Args:
        db: Database session.
        created_by_user_id: UUID of the admin/owner creating the code.
        organization_id: UUID of the org (for scoping).
        label: Optional customer/org label.
        email: Optional intended recipient email.
        expires_in_days: Optional expiration in days from now.

    Returns:
        Dict with: id, code (plaintext), code_prefix, label, email,
        expires_at, created_at, status.
    """
    from uuid import UUID

    # Generate plaintext code
    plaintext_code = generate_invitation_code()
    code_hash = hash_password(plaintext_code)
    code_prefix = _get_code_prefix(plaintext_code)

    # Compute expiration
    expires_at = None
    if expires_in_days and expires_in_days > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

    # Create DB row
    invitation = InvitationCode(
        code_hash=code_hash,
        code_prefix=code_prefix,
        status=InvitationStatus.UNUSED,
        label=label,
        email=email,
        expires_at=expires_at,
        created_by_user_id=UUID(str(created_by_user_id)),
        organization_id=UUID(str(organization_id)),
    )
    db.add(invitation)
    db.commit()
    db.refresh(invitation)

    logger.info(
        "[INVITATION] Created invitation code id=%s org=%s by=%s",
        str(invitation.id)[:8],
        str(organization_id)[:8],
        str(created_by_user_id)[:8],
    )

    return {
        "id": str(invitation.id),
        "code": plaintext_code,  # ONLY time plaintext is returned
        "code_prefix": code_prefix,
        "label": label,
        "email": email,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "created_at": invitation.created_at.isoformat(),
        "status": "unused",
    }


def validate_invitation_code(
    db: Session,
    code: str,
) -> InvitationCode:
    """Validate an invitation code for use during registration.

    Checks:
    1. Code exists (hash lookup)
    2. Status is UNUSED
    3. Not expired
    4. Not revoked

    Args:
        db: Database session.
        code: The plaintext invitation code from the user.

    Returns:
        The validated InvitationCode row.

    Raises:
        InvitationNotFoundError: Code not found.
        InvitationAlreadyUsedError: Code already redeemed.
        InvitationExpiredError: Code past expiration.
        InvitationRevokedError: Code revoked by admin.
    """
    # Search ALL invitations (any status) and check hash
    invitations = db.execute(
        select(InvitationCode)
    ).scalars().all()

    matched = None
    for inv in invitations:
        if verify_password(code, inv.code_hash):
            matched = inv
            break

    if matched is None:
        raise InvitationNotFoundError()

    # Check used — must come BEFORE expired check because a USED code
    # may have a past expiry date, but the correct error is 'already used'.
    if matched.status == InvitationStatus.USED:
        raise InvitationAlreadyUsedError()

    # Check revoked
    if matched.status == InvitationStatus.REVOKED:
        raise InvitationRevokedError()

    # Check expired
    now = datetime.now(timezone.utc)
    if matched.expires_at and matched.expires_at < now:
        matched.status = InvitationStatus.EXPIRED
        db.commit()
        raise InvitationExpiredError()

    return matched


def redeem_invitation(
    db: Session,
    invitation: InvitationCode,
    user_id: Any,
) -> None:
    """Atomically mark an invitation as USED after successful registration.

    Uses a SELECT ... FOR UPDATE pattern via flush + status check to
    prevent double-redemption under concurrency.

    Args:
        db: Database session (same transaction as user creation).
        invitation: The validated InvitationCode row.
        user_id: UUID of the newly created user.
    """
    from uuid import UUID

    # Re-fetch with lock to prevent race conditions
    locked = db.execute(
        select(InvitationCode)
        .where(InvitationCode.id == invitation.id)
        .with_for_update()
    ).scalar_one()

    if locked.status != InvitationStatus.UNUSED:
        # Race condition: another request redeemed it first
        raise InvitationAlreadyUsedError()

    now = datetime.now(timezone.utc)
    locked.status = InvitationStatus.USED
    locked.used_at = now
    locked.used_by_user_id = UUID(str(user_id))
    # Don't commit — let the caller commit as part of their transaction

    logger.info(
        "[INVITATION] Redeemed invitation code id=%s user=%s",
        str(locked.id)[:8],
        str(user_id)[:8],
    )


def list_invitations(
    db: Session,
    organization_id: Any,
    *,
    status_filter: InvitationStatus | None = None,
) -> list[dict[str, Any]]:
    """List all invitations for an organization (admin only).

    Returns safe metadata — NEVER returns code_hash or plaintext code.

    Args:
        db: Database session.
        organization_id: UUID of the org.
        status_filter: Optional filter by status.

    Returns:
        List of dicts with invitation metadata.
    """
    from uuid import UUID

    query = select(InvitationCode).where(
        InvitationCode.organization_id == UUID(str(organization_id))
    )
    if status_filter:
        query = query.where(InvitationCode.status == status_filter)
    query = query.order_by(InvitationCode.created_at.desc())

    invitations = db.execute(query).scalars().all()

    return [
        {
            "id": str(inv.id),
            "code_prefix": inv.code_prefix,
            "status": inv.status.value,
            "label": inv.label,
            "email": inv.email,
            "expires_at": inv.expires_at.isoformat() if inv.expires_at else None,
            "used_at": inv.used_at.isoformat() if inv.used_at else None,
            "revoked_at": inv.revoked_at.isoformat() if inv.revoked_at else None,
            "created_at": inv.created_at.isoformat(),
        }
        for inv in invitations
    ]


def revoke_invitation(
    db: Session,
    invitation_id: Any,
    organization_id: Any,
) -> dict[str, Any]:
    """Revoke an unused invitation code (admin only).

    Args:
        db: Database session.
        invitation_id: UUID of the invitation to revoke.
        organization_id: UUID of the org (for isolation).

    Returns:
        Dict with revocation status.

    Raises:
        InvitationNotFoundError: Invitation not found.
        InvitationError: Invitation is not in UNUSED status.
    """
    from uuid import UUID

    invitation = db.execute(
        select(InvitationCode).where(
            InvitationCode.id == UUID(str(invitation_id)),
            InvitationCode.organization_id == UUID(str(organization_id)),
        )
    ).scalar_one_or_none()

    if invitation is None:
        raise InvitationNotFoundError("Invitation not found.")

    if invitation.status != InvitationStatus.UNUSED:
        raise InvitationError(
            f"Cannot revoke invitation with status '{invitation.status.value}'.",
            error_code="invitation_not_revocable",
        )

    invitation.status = InvitationStatus.REVOKED
    invitation.revoked_at = datetime.now(timezone.utc)
    db.commit()

    logger.info(
        "[INVITATION] Revoked invitation code id=%s org=%s",
        str(invitation.id)[:8],
        str(organization_id)[:8],
    )

    return {
        "id": str(invitation.id),
        "status": "revoked",
        "revoked_at": invitation.revoked_at.isoformat(),
    }


PLATFORM_OWNER_EMAIL = "4rats.com@gmail.com"


def require_owner_or_admin(user: User) -> None:
    """Raise if user is not the platform owner.

    Only the exact platform-owner email is permitted to manage
    invitations.  The comparison is case-insensitive.

    Args:
        user: The authenticated User.

    Raises:
        InvitationError: If user is not authorized (HTTP 403).
    """
    if (user.email or "").lower() != PLATFORM_OWNER_EMAIL.lower():
        raise InvitationError(
            "Invitation management is restricted to the platform owner.",
            error_code="forbidden",
        )
