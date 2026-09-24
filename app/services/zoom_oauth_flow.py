"""Zoom OAuth2 Web Application flow management.

Mirrors the ``GoogleOAuthFlow`` pattern exactly:
  1. State generation (CSRF protection)
  2. Authorization URL construction
  3. Token exchange (authorization code → access + refresh tokens)
  4. Account info fetch
  5. Token storage via CredentialVault
  6. State validation and consumption
  7. Token refresh (before each API call)
  8. Connection status + disconnect

SECURITY:
  - State tokens are cryptographically random (secrets.token_urlsafe)
  - State tokens are single-use (consumed on callback)
  - State tokens expire (configurable TTL, default 10 minutes)
  - Access tokens are stored in encrypted vault only
  - All credential storage is encrypted via CredentialVault
  - Error messages are sanitized to prevent token leakage
  - Tokens are NEVER logged

Usage:
    from app.services.zoom_oauth_flow import ZoomOAuthFlow

    # Step 1: Generate state + auth URL
    state_row = ZoomOAuthFlow.create_authorization_url(
        db=db, org_id=org_id, user_id=user_id,
    )
    # Redirect user to state_row → build_authorization_url()

    # Step 2: Handle callback
    result = ZoomOAuthFlow.exchange_code(
        db=db, code=authorization_code, state=state_token,
    )
"""
from __future__ import annotations

import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models_multi_tenant import IntegrationStatus, ZoomOAuthState
from app.services.zoom_api_client import ZoomTokenExchangeError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ZoomOAuthError(Exception):
    """Base exception for Zoom OAuth flow errors."""

    def __init__(self, message: str, error_code: str = "zoom_oauth_error"):
        super().__init__(message)
        self.error_code = error_code


class ZoomOAuthStateError(ZoomOAuthError):
    """Raised when OAuth state validation fails."""

    def __init__(self, message: str):
        super().__init__(message, error_code="zoom_invalid_state")


class ZoomOAuthTokenExchangeError(ZoomOAuthError):
    """Raised when token exchange with Zoom fails."""

    def __init__(self, message: str):
        super().__init__(message, error_code="zoom_token_exchange_failed")


class ZoomOAuthDenialError(ZoomOAuthError):
    """Raised when user denies access at Zoom consent screen."""

    def __init__(self):
        super().__init__(
            "Authorization was denied by the user.",
            error_code="zoom_access_denied",
        )


# ---------------------------------------------------------------------------
# Flow class
# ---------------------------------------------------------------------------


class ZoomOAuthFlow:
    """Manages the complete Zoom OAuth2 Web Application flow."""

    # ------------------------------------------------------------------
    # Step 1: Create authorization URL
    # ------------------------------------------------------------------

    @staticmethod
    def create_authorization_url(
        db: Session,
        org_id: Any,
        user_id: Any,
        *,
        scopes: list[str] | None = None,
    ) -> ZoomOAuthState:
        """Generate a state token and build the Zoom authorization URL.

        Args:
            db: Database session
            org_id: Organization UUID
            user_id: User UUID
            scopes: Optional scopes (informational — Zoom scopes are
                    configured in Marketplace, not in the URL).

        Returns:
            ZoomOAuthState row with state_token.

        Raises:
            ZoomOAuthError: If Zoom client is not configured.
        """
        from app.services.credential_vault import (
            CredentialCorruptError,
            CredentialNotFoundError,
        )
        from app.services.integration_config_resolver import IntegrationConfigResolver

        # Resolve Zoom credentials from org vault — org must configure their own
        try:
            zoom_cfg = IntegrationConfigResolver.resolve_zoom_config(db, org_id)
        except (CredentialNotFoundError, CredentialCorruptError):
            zoom_cfg = None

        # Org-owned model: credentials MUST come from org vault
        if zoom_cfg and zoom_cfg.client_id and zoom_cfg.redirect_uri:
            redirect_uri = zoom_cfg.redirect_uri
        else:
            logger.warning(
                "[ZOOM_OAUTH] Zoom OAuth not configured for org=%s — "
                "no org-specific Zoom credentials found.",
                str(org_id)[:8],
            )
            raise ZoomOAuthError(
                "Zoom is not configured for your organization. "
                "Please go to Integrations and configure your Zoom "
                "OAuth credentials (Client ID, Client Secret, Redirect URI).",
                error_code="zoom_client_not_configured",
            )

        # Convert string IDs to UUIDs if needed
        org_uuid = (
            uuid.UUID(str(org_id))
            if not isinstance(org_id, uuid.UUID)
            else org_id
        )
        user_uuid = (
            uuid.UUID(str(user_id))
            if not isinstance(user_id, uuid.UUID)
            else user_id
        )

        # Generate cryptographically random state token
        state_token = secrets.token_urlsafe(32)

        # Calculate expiry
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(
            minutes=settings.zoom_oauth_state_ttl_minutes
        )

        # redirect_uri already resolved from org vault above

        # Persist state in database
        state_row = ZoomOAuthState(
            organization_id=org_uuid,
            user_id=user_uuid,
            state_token=state_token,
            redirect_uri=redirect_uri,
            scopes=scopes or ["meeting:write"],
            expires_at=expires_at,
            used=False,
        )
        db.add(state_row)

        # Purge expired states for this org (housekeeping)
        _purge_expired_states(db, org_uuid)

        db.commit()
        db.refresh(state_row)

        logger.info(
            "[ZOOM_OAUTH] Created authorization state",
            extra={
                "org_id": str(org_uuid),
                "user_id": str(user_uuid),
                "expires_at": expires_at.isoformat(),
            },
        )
        return state_row

    @staticmethod
    def build_authorization_url(
        state_token: str,
        redirect_uri: str,
        client_id: str | None = None,
    ) -> str:
        """Build the Zoom OAuth2 authorization URL.

        Args:
            state_token: The CSRF state token.
            redirect_uri: Where Zoom redirects after auth.
            client_id: Optional client_id override. If None, uses platform default.

        Returns:
            Full authorization URL string.
        """
        from app.services.zoom_api_client import ZoomAPIClient

        if not client_id:
            raise ZoomOAuthError(
                "Zoom client_id is required to build authorization URL. "
                "Please configure your Zoom credentials in Integrations.",
                error_code="zoom_client_not_configured",
            )

        return ZoomAPIClient.build_authorization_url(
            client_id=client_id,
            redirect_uri=redirect_uri,
            state_token=state_token,
        )

    # ------------------------------------------------------------------
    # Step 2: Exchange authorization code for tokens
    # ------------------------------------------------------------------

    @staticmethod
    def exchange_code(
        db: Session,
        code: str,
        state: str,
    ) -> dict[str, Any]:
        """Validate state and exchange authorization code for tokens.

        Args:
            db: Database session
            code: Authorization code from Zoom callback
            state: State token from Zoom callback

        Returns:
            Dict with refresh_token, email, account_id, organization_id.

        Raises:
            ZoomOAuthStateError: If state is invalid/expired/reused.
            ZoomOAuthTokenExchangeError: If token exchange fails.
            ZoomOAuthDenialError: If user denied access.
        """
        from app.services.credential_vault import CredentialVault
        from app.services.integration_config_resolver import IntegrationConfigResolver
        from app.services.zoom_api_client import ZoomAPIClient

        # --- Validate state ---
        state_row = _validate_state(db, state)

        # Mark state as used (single-use) BEFORE exchange to prevent race
        # conditions where two concurrent callbacks both pass validation.
        state_row.used = True
        db.flush()  # flush only — commit happens after successful exchange

        # --- Resolve Zoom credentials from org vault ---
        # Org-owned model: credentials MUST come from org vault
        try:
            zoom_cfg = IntegrationConfigResolver.resolve_zoom_config(
                db, state_row.organization_id
            )
            resolved_client_id = zoom_cfg.client_id
            resolved_client_secret = zoom_cfg.client_secret
            resolved_redirect_uri = zoom_cfg.redirect_uri or state_row.redirect_uri
        except Exception as exc:
            db.rollback()
            raise ZoomOAuthTokenExchangeError(
                "Zoom credentials not configured for this organization. "
                "Please configure your Zoom OAuth credentials in the "
                "Integrations dashboard."
            ) from exc

        try:
            # --- Exchange code for tokens ---
            token_data = ZoomAPIClient.exchange_code(
                code=code,
                client_id=resolved_client_id,
                client_secret=resolved_client_secret,
                redirect_uri=resolved_redirect_uri,
            )

            # --- Fetch account info ---
            account_info = ZoomAPIClient.get_account_info(
                access_token=token_data["access_token"]
            )
        except ZoomTokenExchangeError:
            # Rollback state marking so user can retry without re-initiating
            db.rollback()
            raise ZoomOAuthTokenExchangeError(
                "Failed to exchange authorization code with Zoom. "
                "Please verify your Zoom OAuth credentials and try again."
            )
        except Exception:
            # Rollback state marking so user can retry without re-initiating
            db.rollback()
            raise

        # --- Compute token expiry ---
        now = datetime.now(timezone.utc)
        token_expires_at = now + timedelta(
            seconds=token_data.get("expires_in", 3600)
        )

        # --- Store credentials in vault (org-scoped, encrypted) ---
        credentials = {
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token", ""),
            "client_id": resolved_client_id,
            "client_secret": resolved_client_secret,
            "redirect_uri": resolved_redirect_uri,
        }
        metadata = {
            "account_id": account_info.get("account_id", ""),
            "account_email": account_info.get("email", ""),
            "connected_at": now.isoformat(),
            "token_expires_at": token_expires_at.isoformat(),
            "scopes": token_data.get("scope", "meeting:write").split(),
        }

        CredentialVault.save_credentials(
            db=db,
            org_id=state_row.organization_id,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials=credentials,
            metadata=metadata,
            status=IntegrationStatus.CONNECTED,
        )

        email = account_info.get("email", "")

        logger.info(
            "[ZOOM_OAUTH] OAuth flow completed successfully",
            extra={
                "org_id": str(state_row.organization_id),
                "email": email,
            },
        )

        return {
            "refresh_token": token_data.get("refresh_token", ""),
            "email": email,
            "account_id": account_info.get("account_id", ""),
            "organization_id": str(state_row.organization_id),
        }

    # ------------------------------------------------------------------
    # Step 3: Check connection status
    # ------------------------------------------------------------------

    @staticmethod
    def get_connection_status(db: Session, org_id: Any) -> dict[str, Any]:
        """Get Zoom OAuth connection status for an organization.

        Args:
            db: Database session
            org_id: Organization UUID

        Returns:
            Dict with connected status, metadata, never credentials.

        SECURITY: Never returns credentials, tokens, or secrets.
        """
        from app.services.credential_vault import CredentialVault

        org_uuid = (
            uuid.UUID(str(org_id))
            if not isinstance(org_id, uuid.UUID)
            else org_id
        )

        has_creds = CredentialVault.has_credentials(
            db, org_uuid, "zoom", "zoom_oauth"
        )
        metadata = CredentialVault.get_safe_metadata(
            db, org_uuid, "zoom", "zoom_oauth"
        ) or {}

        return {
            "provider": "zoom",
            "integration_type": "zoom_oauth",
            "connected": has_creds,
            "account_id": metadata.get("account_id") if has_creds else None,
            "account_email": metadata.get("account_email") if has_creds else None,
            "connected_at": metadata.get("connected_at") if has_creds else None,
        }

    # ------------------------------------------------------------------
    # Step 4: Disconnect
    # ------------------------------------------------------------------

    @staticmethod
    def disconnect(db: Session, org_id: Any) -> dict[str, Any]:
        """Disconnect Zoom OAuth for an organization.

        Clears credentials, metadata, and sets status to DISCONNECTED.

        Args:
            db: Database session
            org_id: Organization UUID

        Returns:
            Dict with disconnect status.
        """
        from app.services.credential_vault import CredentialVault

        org_uuid = (
            uuid.UUID(str(org_id))
            if not isinstance(org_id, uuid.UUID)
            else org_id
        )

        result = CredentialVault.disconnect(
            db, org_uuid, "zoom", "zoom_oauth"
        )

        logger.info(
            "[ZOOM_OAUTH] Zoom OAuth disconnected",
            extra={"org_id": str(org_uuid)},
        )

        return {
            "provider": "zoom",
            "integration_type": "zoom_oauth",
            "connected": False,
            "disconnected": result is not None,
        }

    # ------------------------------------------------------------------
    # Step 6: Token refresh
    # ------------------------------------------------------------------

    @staticmethod
    def refresh_token_if_needed(db: Session, org_id: Any) -> str:
        """Ensure a valid access token exists, refreshing if necessary.

        This is called before every Zoom API interaction.  It checks the
        ``token_expires_at`` metadata field and, if the token is expired
        or about to expire, uses the stored refresh token to obtain a
        new access token.  The new tokens are persisted in the vault.

        Args:
            db: Database session
            org_id: Organization UUID

        Returns:
            A valid access token string.

        Raises:
            ZoomTokenRefreshError: If refresh fails.
            ZoomOAuthError: If no credentials exist.
        """
        from app.services.credential_vault import CredentialVault
        from app.services.zoom_api_client import (
            ZoomAPIClient,
            ZoomTokenRefreshError,
            is_token_expired,
        )

        org_uuid = (
            uuid.UUID(str(org_id))
            if not isinstance(org_id, uuid.UUID)
            else org_id
        )

        # Get current credentials
        credentials = CredentialVault.get_credentials(
            db, org_uuid, "zoom", "zoom_oauth"
        )

        access_token = credentials.get("access_token", "")
        refresh_token = credentials.get("refresh_token", "")
        client_id = credentials.get("client_id", "")
        client_secret = credentials.get("client_secret", "")

        # Client ID and secret MUST be in vault credentials
        if not client_id or not client_secret:
            raise ZoomOAuthError(
                "Zoom credentials incomplete: client_id or client_secret "
                "missing from vault. Please re-save your Zoom credentials "
                "in the Integrations dashboard.",
                error_code="zoom_credentials_incomplete",
            )

        # Check metadata for expiry
        metadata = CredentialVault.get_safe_metadata(
            db, org_uuid, "zoom", "zoom_oauth"
        ) or {}
        expires_at_str = metadata.get("token_expires_at")
        expires_at = None
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(expires_at_str)
            except (ValueError, TypeError):
                expires_at = None

        if not is_token_expired(expires_at):
            return access_token

        # Token is expired or about to expire — refresh
        if not refresh_token:
            raise ZoomOAuthError(
                "Zoom refresh token not available. "
                "Please reconnect Zoom OAuth.",
                error_code="zoom_no_refresh_token",
            )

        logger.info(
            "[ZOOM_OAUTH] Refreshing Zoom access token",
            extra={"org_id": str(org_uuid)},
        )

        try:
            token_data = ZoomAPIClient.refresh_access_token(
                refresh_token=refresh_token,
                client_id=client_id,
                client_secret=client_secret,
            )
        except ZoomTokenRefreshError as exc:
            # ── invalid_grant / permanently revoked token ─────────────
            # Mark the integration as ERROR so:
            #  • has_credentials() consumers see the error state
            #  • the dashboard shows "reconnect needed"
            #  • we don't silently retry a permanently invalid token
            #
            # We do NOT clear credentials — the client_id/client_secret
            # are still valid; only the refresh token is revoked.  The
            # user can reconnect via /auth/zoom/start without re-entering
            # client credentials.
            logger.warning(
                "[ZOOM_OAUTH] Zoom token refresh failed — "
                "marking integration as ERROR for org %s",
                str(org_uuid),
            )
            try:
                CredentialVault.mark_error(
                    db=db,
                    org_id=org_uuid,
                    provider="zoom",
                    integration_type="zoom_oauth",
                    error_message=str(exc),
                )
            except Exception:
                # Non-fatal — vault write failure shouldn't mask the
                # original Zoom error.
                logger.exception(
                    "[ZOOM_OAUTH] Failed to mark integration error for org %s",
                    str(org_uuid),
                )
            raise

        # Compute new expiry
        now = datetime.now(timezone.utc)
        new_expires_at = now + timedelta(
            seconds=token_data.get("expires_in", 3600)
        )

        # Update stored credentials — preserve redirect_uri from vault
        redirect_uri = credentials.get("redirect_uri", "")
        new_credentials = {
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token", refresh_token),
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
        }
        new_metadata = dict(metadata)
        new_metadata["token_expires_at"] = new_expires_at.isoformat()
        new_metadata["connected_at"] = metadata.get(
            "connected_at", now.isoformat()
        )

        CredentialVault.save_credentials(
            db=db,
            org_id=org_uuid,
            provider="zoom",
            integration_type="zoom_oauth",
            credentials=new_credentials,
            metadata=new_metadata,
            status=IntegrationStatus.CONNECTED,
        )

        # Refresh succeeded — ensure integration is marked CONNECTED
        # (in case it was previously marked ERROR by a failed refresh).
        try:
            CredentialVault.mark_connected(
                db=db,
                org_id=org_uuid,
                provider="zoom",
                integration_type="zoom_oauth",
            )
        except Exception:
            logger.debug(
                "[ZOOM_OAUTH] Could not mark_connected for org %s",
                str(org_uuid),
            )

        logger.info(
            "[ZOOM_OAUTH] Zoom access token refreshed successfully",
            extra={"org_id": str(org_uuid)},
        )

        return token_data["access_token"]


# =====================================================================
# Internal helpers
# =====================================================================


def _validate_state(db: Session, state_token: str) -> ZoomOAuthState:
    """Validate and return a state token.

    Checks:
      1. State exists in database
      2. State has not been used
      3. State has not expired

    Returns:
        ZoomOAuthState row

    Raises:
        ZoomOAuthStateError: If any validation check fails.
    """
    stmt = select(ZoomOAuthState).where(
        ZoomOAuthState.state_token == state_token
    )
    state_row = db.execute(stmt).scalar_one_or_none()

    if state_row is None:
        raise ZoomOAuthStateError("Invalid OAuth state parameter.")

    if state_row.used:
        logger.warning(
            "[ZOOM_OAUTH] Reused OAuth state detected",
            extra={
                "org_id": str(state_row.organization_id),
                "state_id": str(state_row.id),
            },
        )
        raise ZoomOAuthStateError(
            "OAuth state has already been used. Please try connecting again."
        )

    now = datetime.now(timezone.utc)
    # SQLite strips timezone info on storage; re-attach for comparison
    expires_at = state_row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        logger.warning(
            "[ZOOM_OAUTH] Expired OAuth state",
            extra={
                "org_id": str(state_row.organization_id),
                "state_id": str(state_row.id),
                "expired_at": state_row.expires_at.isoformat(),
            },
        )
        raise ZoomOAuthStateError(
            "OAuth state has expired. Please try connecting again."
        )

    return state_row


def _purge_expired_states(db: Session, org_id: uuid.UUID) -> None:
    """Delete expired OAuth states for an org (housekeeping).

    Mirrors the Google OAuth pattern.
    """
    from sqlalchemy import delete as sa_delete

    # Use tz-naive UTC for SQLAlchemy comparison (SQLite stores naive datetimes)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    db.execute(
        sa_delete(ZoomOAuthState).where(
            ZoomOAuthState.organization_id == org_id,
            ZoomOAuthState.expires_at < now,
        )
    )
