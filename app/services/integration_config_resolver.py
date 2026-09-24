"""Integration Configuration Resolver — credential resolution for services.

Resolves external service credentials for a specific organization with
the following precedence:

    1. Organization-specific credential (from credential vault / org_integrations)
    2. Platform default credential (from .env / settings)
    3. Clear configuration error

This module is the single source of truth for "what credentials should
service X use for organization Y?".

DESIGN:
  - All methods are stateless classmethods
  - Never exposes raw credentials in return types (only dataclass fields)
  - Never logs credential values
  - Falls back gracefully to platform defaults
  - Returns descriptive errors when nothing is configured

SECURITY:
  - This resolver never logs API keys, OAuth tokens, or other secrets
  - Return values are used only within the service layer
  - API responses must NOT expose these values
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.config import settings
from app.services.credential_vault import (
    CredentialCorruptError,
    CredentialNotFoundError,
    CredentialVault,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Resolved configuration dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GoogleOAuthConfig:
    """Resolved Google OAuth2 credentials for an organization.

    Used by CalendarService and EmailService to build Google API
    credentials without depending on a token.json file.
    """
    client_id: str
    client_secret: str
    refresh_token: str


@dataclass(frozen=True)
class GoogleCalendarConfig:
    """Resolved Google Calendar configuration."""
    calendar_id: str


@dataclass(frozen=True)
class GmailConfig:
    """Resolved Gmail sender configuration."""
    sender_email: str


@dataclass(frozen=True)
class AIProviderConfig:
    """Resolved AI provider configuration for one provider (primary or fallback)."""
    api_key: str
    base_url: str
    model: str
    provider_id: str = "openai"


@dataclass(frozen=True)
class AIConfig:
    """Resolved AI configuration — primary + optional fallback provider.

    The primary config is always present (may come from platform defaults).
    The fallback is only populated when all three fields (key, url, model)
    are configured.
    """
    primary: AIProviderConfig
    fallback: AIProviderConfig | None = None


@dataclass(frozen=True)
class BrandingConfig:
    """Resolved organization branding for emails, calendar events, and AI.

    All fields have safe defaults so callers never need to handle None.
    When an organization has not configured branding, defaults are derived
    from the platform settings.
    """
    company_name: str = "Strategy Call Agent"
    sender_name: str = "Strategy Call Agent"
    brand_color: str = "#1a73e8"
    tagline: str = ""


@dataclass(frozen=True)
class MeetingConfig:
    """Resolved meeting configuration for an organization."""
    duration_minutes: int = 30


@dataclass(frozen=True)
class ZoomOAuthConfig:
    """Resolved Zoom OAuth2 credentials for an organization.

    Used by ZoomMeetingService to authenticate with the Zoom API.
    client_id and client_secret are always required.
    redirect_uri is organization-specific (each org configures their own).
    account_id is optional — populated after OAuth callback from Zoom API.
    """
    account_id: str
    client_id: str
    client_secret: str
    redirect_uri: str = ""


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


class ConfigurationError(RuntimeError):
    """Raised when an organization's integration credentials are missing or
    incomplete in the credential vault.

    In production, services MUST use vault-stored credentials. This error
    replaces the previous silent .env fallback which masked missing
    org-level configuration.
    """


class IntegrationConfigResolver:
    """Resolves integration credentials for a specific organization.

    Every method follows the same pattern:
      1. Try to load org-specific credentials from the credential vault
      2. If found and valid, return them
      3. Otherwise, fall back to platform defaults from settings/.env
      4. If nothing is configured at all, raise a clear error

    All methods are classmethods — no instance state, no database
    connections held. Each call opens a vault lookup via the provided db
    session.
    """

    # ─── Google OAuth ────────────────────────────────────────────────

    @staticmethod
    def resolve_google_oauth(
        db: Session, org_id: uuid.UUID
    ) -> GoogleOAuthConfig:
        """Resolve Google OAuth2 tokens for an organization.

        Org-specific credentials (stored via credential vault) take
        precedence over platform defaults from .env.

        Resolution order:
          1. Vault has client_id + client_secret (pre-OAuth or post-OAuth)
          2. .env fallback (development/bootstrap only — NEVER in production)

        BUG FIX (Phase 6D): The previous .env fallback silently returned
        credentials even in production when the vault was empty.  This
        masked the fact that no org-level credentials existed, causing
        confusing downstream errors (e.g., empty refresh_token →
        GoogleAuthError from file-based fallback).  Now:
        - If vault has a record with incomplete credentials → raise
          ConfigurationError immediately (do NOT mask with .env values).
        - If vault is empty AND app_env is "production" → raise
          ConfigurationError (org must configure credentials via Dashboard).
        - If vault is empty AND app_env is dev/test → fall back to .env.

        SECURITY: Never logs credential values.
        """
        # 1. Try org-specific credentials from vault
        _vault_record_exists = False
        try:
            creds = CredentialVault.get_credentials(
                db, org_id, "google", "google_oauth"
            )
            if creds:
                _vault_record_exists = True
                client_id = creds.get("client_id", "")
                client_secret = creds.get("client_secret", "")
                refresh_token = creds.get("refresh_token", "")

                # Vault credentials are authoritative if they have BOTH
                # client_id AND client_secret — the two fields required for
                # the OAuth flow.  refresh_token may not exist yet (it's only
                # obtained after a successful callback).
                if client_id and client_secret:
                    logger.debug(
                        "resolved Google OAuth from org vault for org=%s "
                        "(source=vault, has_refresh_token=%s)",
                        str(org_id)[:8],
                        bool(refresh_token),
                    )
                    return GoogleOAuthConfig(
                        client_id=client_id,
                        client_secret=client_secret,
                        refresh_token=refresh_token,
                    )
                else:
                    # Vault record exists but credentials are incomplete —
                    # DO NOT mask this with .env values.
                    raise ConfigurationError(
                        f"Google OAuth credentials for organization "
                        f"{str(org_id)[:8]}… are incomplete in the vault "
                        f"(client_id={'set' if client_id else 'missing'}, "
                        f"client_secret={'set' if client_secret else 'missing'}). "
                        f"Please complete the configuration in "
                        f"Integrations → Google."
                    )
        except ConfigurationError:
            raise  # re-raise — already has a clear message
        except (CredentialNotFoundError, CredentialCorruptError):
            pass
        except Exception as exc:
            logger.warning(
                "failed to read org Google OAuth from vault: %s", exc
            )

        # 2. Vault is empty — .env fallback is ONLY for dev/test.
        if settings.app_env == "production":
            raise ConfigurationError(
                f"Google OAuth credentials are not configured for organization "
                f"{str(org_id)[:8]}…  In production, you MUST save your "
                f"Google OAuth credentials in the Dashboard → Integrations → "
                f"Google page before connecting.  The legacy .env fallback "
                f"is disabled in production."
            )

        logger.debug(
            "Google OAuth falling back to .env defaults for org=%s (env=%s)",
            str(org_id)[:8],
            settings.app_env,
        )
        return GoogleOAuthConfig(
            client_id=settings.google_client_id,
            client_secret=settings.google_client_secret,
            refresh_token=settings.google_refresh_token,
        )

    # ─── Google Calendar ────────────────────────────────────────────

    @staticmethod
    def resolve_calendar_config(
        db: Session, org_id: uuid.UUID
    ) -> GoogleCalendarConfig:
        """Resolve calendar_id for an organization.

        Checks org-specific calendar config in vault first,
        then falls back to platform default (settings.calendar_id).
        """
        try:
            creds = CredentialVault.get_credentials(
                db, org_id, "google", "calendar"
            )
            cal_id = creds.get("calendar_id", "")
            if cal_id:
                logger.debug(
                    "resolved calendar config from org vault for org=%s",
                    str(org_id)[:8],
                )
                return GoogleCalendarConfig(calendar_id=cal_id)
        except (CredentialNotFoundError, CredentialCorruptError):
            pass
        except Exception as exc:
            logger.warning(
                "failed to read org calendar config from vault: %s", exc
            )

        return GoogleCalendarConfig(
            calendar_id=settings.calendar_id or "primary"
        )

    # ─── Gmail ──────────────────────────────────────────────────────

    @staticmethod
    def resolve_gmail_config(
        db: Session, org_id: uuid.UUID
    ) -> GmailConfig:
        """Resolve Gmail sender email for an organization."""
        try:
            creds = CredentialVault.get_credentials(
                db, org_id, "google", "email"
            )
            sender = creds.get("sender_email", "")
            if sender:
                logger.debug(
                    "resolved Gmail config from org vault for org=%s",
                    str(org_id)[:8],
                )
                return GmailConfig(sender_email=sender)
        except (CredentialNotFoundError, CredentialCorruptError):
            pass
        except Exception as exc:
            logger.warning(
                "failed to read org Gmail config from vault: %s", exc
            )

        return GmailConfig(sender_email=settings.gmail_sender)

    # ─── AI Provider ────────────────────────────────────────────────

    @staticmethod
    def resolve_ai_config(
        db: Session, org_id: uuid.UUID
    ) -> AIConfig:
        """Resolve AI provider configuration for an organization.

        Org-specific API key/model/base_url take precedence over platform
        defaults. The fallback provider always comes from platform defaults
        (customers are not expected to configure a separate fallback).

        Raises RuntimeError if neither org nor platform has a valid
        primary AI configuration.
        """
        # 1. Try org-specific AI credentials
        primary = IntegrationConfigResolver._resolve_ai_primary(db, org_id)
        if primary is not None:
            # Org has its own AI config — use platform fallback
            fallback = IntegrationConfigResolver._get_platform_fallback()
            return AIConfig(primary=primary, fallback=fallback)

        # 2. Fall back to platform defaults
        platform_primary = IntegrationConfigResolver._get_platform_primary()
        if platform_primary is not None:
            fallback = IntegrationConfigResolver._get_platform_fallback()
            return AIConfig(primary=platform_primary, fallback=fallback)

        # 3. Nothing configured
        raise RuntimeError(
            "AI provider not configured: no organization-specific or "
            "platform AI credentials found. Set AI_BASE_URL, AI_API_KEY, "
            "and AI_MODEL in .env, or configure via the organization API."
        )

    @staticmethod
    def _resolve_ai_primary(
        db: Session, org_id: uuid.UUID
    ) -> AIProviderConfig | None:
        """Try to load org-specific AI primary provider from vault.

        Reads credentials from the vault key ("openai", "ai_provider").
        Supports both new-style (metadata has provider_id) and old-style
        (no provider_id = legacy OpenAI) configurations.
        """
        try:
            creds = CredentialVault.get_credentials(
                db, org_id, "openai", "ai_provider"
            )
            meta = CredentialVault.get_safe_metadata(
                db, org_id, "openai", "ai_provider"
            ) or {}

            api_key = creds.get("api_key", "")
            if api_key:
                # New-style: provider_id stored in metadata
                # Old-style: no provider_id means legacy "openai"
                provider_id = meta.get("provider_id", "openai")
                return AIProviderConfig(
                    api_key=api_key,
                    base_url=creds.get("base_url", settings.ai_base_url),
                    model=meta.get("model", settings.ai_model),
                    provider_id=provider_id,
                )
        except (CredentialNotFoundError, CredentialCorruptError):
            pass
        except Exception as exc:
            logger.warning(
                "failed to read org AI credentials from vault: %s", exc
            )
        return None

    @staticmethod
    def _get_platform_primary() -> AIProviderConfig | None:
        """Return the platform default AI primary provider, or None."""
        if settings.ai_api_key and settings.ai_base_url and settings.ai_model:
            return AIProviderConfig(
                api_key=settings.ai_api_key,
                base_url=settings.ai_base_url,
                model=settings.ai_model,
            )
        return None

    @staticmethod
    def _get_platform_fallback() -> AIProviderConfig | None:
        """Return the platform default AI fallback provider, or None."""
        if (
            settings.ai_fallback_api_key
            and settings.ai_fallback_base_url
            and settings.ai_fallback_model
        ):
            return AIProviderConfig(
                api_key=settings.ai_fallback_api_key,
                base_url=settings.ai_fallback_base_url,
                model=settings.ai_fallback_model,
            )
        return None

    # ─── Timezone ───────────────────────────────────────────────────

    @staticmethod
    def resolve_timezone(
        db: Session, org_id: uuid.UUID
    ) -> str:
        """Resolve the business timezone for an organization.

        Checks the Organization model first, falls back to the platform
        default from settings.
        """
        from app.models_multi_tenant import Organization

        org = db.query(Organization).filter(Organization.id == org_id).first()
        if org and org.timezone:
            return org.timezone
        return settings.business_timezone

    # ─── Branding ───────────────────────────────────────────────────

    @staticmethod
    def resolve_branding(
        db: Session, org_id: uuid.UUID
    ) -> BrandingConfig:
        """Resolve organization branding for emails, calendar, and AI.

        Checks the Organization model fields (sender_name, brand_color,
        tagline) and falls back to platform defaults when not set.

        The company_name is taken from Organization.name — every org
        always has a name, so no fallback is needed for that field.
        """
        from app.models_multi_tenant import Organization

        org = db.query(Organization).filter(Organization.id == org_id).first()
        if org is None:
            return BrandingConfig()

        return BrandingConfig(
            company_name=org.name or "Strategy Call Agent",
            sender_name=org.sender_name or org.name or "Strategy Call Agent",
            brand_color=org.brand_color or "#1a73e8",
            tagline=org.tagline or "",
        )

    # ─── Meeting Duration ───────────────────────────────────────────

    @staticmethod
    def resolve_meeting_config(
        db: Session, org_id: uuid.UUID
    ) -> MeetingConfig:
        """Resolve meeting duration for an organization.

        Checks OrgScheduleConfig.meeting_duration_minutes first,
        falls back to the platform default (30 minutes).
        """
        from app.models_multi_tenant import OrgScheduleConfig

        cfg = db.query(OrgScheduleConfig).filter(
            OrgScheduleConfig.organization_id == org_id
        ).first()
        if cfg and cfg.meeting_duration_minutes is not None:
            return MeetingConfig(duration_minutes=cfg.meeting_duration_minutes)
        return MeetingConfig()

    # ─── Zoom OAuth ────────────────────────────────────────────────

    @staticmethod
    def resolve_zoom_config(
        db: Session, org_id: uuid.UUID
    ) -> ZoomOAuthConfig:
        """Resolve Zoom OAuth2 credentials for an organization.

        Org-specific credentials (stored via credential vault) take
        precedence over platform defaults from settings/.env.

        Raises CredentialNotFoundError if neither org nor platform
        credentials are available.
        """
        # 1. Try org-specific credentials from vault
        try:
            creds = CredentialVault.get_credentials(
                db, org_id, "zoom", "zoom_oauth"
            )
            account_id = (creds.get("account_id") or "").strip()
            client_id = (creds.get("client_id") or "").strip()
            client_secret = (creds.get("client_secret") or "").strip()
            redirect_uri = (creds.get("redirect_uri") or "").strip()

            if client_id and client_secret and redirect_uri:
                logger.debug(
                    "resolved Zoom OAuth from org vault for org=%s",
                    str(org_id)[:8],
                )
                return ZoomOAuthConfig(
                    account_id=account_id,
                    client_id=client_id,
                    client_secret=client_secret,
                    redirect_uri=redirect_uri,
                )
            else:
                missing = []
                if not client_id:
                    missing.append("client_id")
                if not client_secret:
                    missing.append("client_secret")
                if not redirect_uri:
                    missing.append("redirect_uri")
                logger.debug(
                    "org vault Zoom credentials incomplete for org=%s "
                    "(missing: %s) — trying platform fallback",
                    str(org_id)[:8],
                    ", ".join(missing),
                )
        except (CredentialNotFoundError, CredentialCorruptError):
            logger.debug(
                "no org vault Zoom credentials for org=%s — "
                "trying platform fallback",
                str(org_id)[:8],
            )
        except Exception as exc:
            logger.warning(
                "failed to read org Zoom OAuth from vault: %s", exc
            )

        # 2. Fall back to platform defaults from settings / .env
        platform_client_id = (settings.zoom_client_id or "").strip()
        platform_client_secret = (settings.zoom_client_secret or "").strip()
        platform_redirect_uri = (settings.zoom_redirect_uri or "").strip()

        if platform_client_id and platform_client_secret and platform_redirect_uri:
            logger.debug(
                "resolved Zoom OAuth from platform defaults for org=%s",
                str(org_id)[:8],
            )
            return ZoomOAuthConfig(
                account_id="",
                client_id=platform_client_id,
                client_secret=platform_client_secret,
                redirect_uri=platform_redirect_uri,
            )

        # 3. Nothing configured at all
        raise CredentialNotFoundError(
            "Zoom OAuth not configured: no organization-specific or "
            "platform Zoom credentials found. Set ZOOM_CLIENT_ID, "
            "ZOOM_CLIENT_SECRET, and ZOOM_REDIRECT_URI in .env, or "
            "configure via the Integrations dashboard."
        )
