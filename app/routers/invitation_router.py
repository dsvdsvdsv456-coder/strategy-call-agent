"""Invitation code router — invite-only account creation (admin endpoints).

Endpoints:
  POST /auth/invitations/generate  — Generate a new invitation code (platform-owner only)
  GET  /auth/invitations           — List all invitations for the org (platform-owner only)
  POST /auth/invitations/{id}/revoke — Revoke an unused invitation (platform-owner only)

SECURITY:
  - Only the platform-owner account (4rats.com@gmail.com) can generate, list, or revoke invitations.
  - Invitation codes are NEVER returned in list/detail responses.
  - Plaintext code is ONLY returned at generation time.
  - Organization isolation: each org can only manage its own invitations.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models_multi_tenant import User
from app.schemas_auth import (
    InvitationGenerateRequest,
    InvitationGenerateResponse,
    InvitationInfo,
    InvitationListResponse,
    MessageResponse,
)
from app.services.invitation_service import (
    InvitationError,
    create_invitation,
    list_invitations,
    require_owner_or_admin,
    revoke_invitation,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/invitations", tags=["invitations"])


@router.post(
    "/generate",
    response_model=InvitationGenerateResponse,
    status_code=status.HTTP_201_CREATED,
)
def generate_invitation(
    payload: InvitationGenerateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> InvitationGenerateResponse:
    """Generate a new invitation code (platform-owner only).

    Returns the plaintext code exactly once. The code is never stored
    in plaintext — only its bcrypt hash is persisted.

    SECURITY:
      - Platform-owner email required (4rats.com@gmail.com)
      - Code is shown only at creation time
      - Code hash is stored, plaintext is discarded
    """
    try:
        require_owner_or_admin(current_user)
    except InvitationError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    try:
        result = create_invitation(
            db=db,
            created_by_user_id=current_user.id,
            organization_id=current_user.organization_id,
            label=payload.label,
            email=payload.email,
            expires_in_days=payload.expires_in_days,
        )
    except Exception as exc:
        logger.exception("Failed to generate invitation")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate invitation code.",
        ) from exc

    return InvitationGenerateResponse(**result)


@router.get(
    "",
    response_model=InvitationListResponse,
)
def get_invitations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> InvitationListResponse:
    """List all invitations for the organization (platform-owner only).

    SECURITY:
      - Platform-owner email required (4rats.com@gmail.com)
      - Only returns invitations for the current org
      - NEVER returns code_hash or plaintext code
    """
    try:
        require_owner_or_admin(current_user)
    except InvitationError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    invitations = list_invitations(db, current_user.organization_id)

    return InvitationListResponse(
        invitations=[InvitationInfo(**inv) for inv in invitations],
        total=len(invitations),
    )


@router.post(
    "/{invitation_id}/revoke",
    response_model=MessageResponse,
)
def revoke(
    invitation_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MessageResponse:
    """Revoke an unused invitation code (platform-owner only).

    SECURITY:
      - Platform-owner email required (4rats.com@gmail.com)
      - Only UNUSED invitations can be revoked
      - Organization isolation enforced
    """
    try:
        require_owner_or_admin(current_user)
    except InvitationError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    try:
        result = revoke_invitation(
            db=db,
            invitation_id=invitation_id,
            organization_id=current_user.organization_id,
        )
    except InvitationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return MessageResponse(message="Invitation revoked successfully.")
