"""Create google_oauth_states table.

The ``google_oauth_states`` table stores CSRF state tokens for the
Google OAuth2 authorization code flow.  Each row represents a
pending OAuth authorization request.

The application model (``GoogleOAuthState`` in ``models_multi_tenant.py``)
and service (``GoogleOAuthFlow`` in ``services/google_oauth_flow.py``)
already reference this table, but no prior migration created it,
causing ``relation "google_oauth_states" does not exist`` on fresh
databases.

Schema mirrors ``zoom_oauth_states`` (migration 015) with one
materialised difference: ``redirect_uri`` is NULLABLE here because
the Google flow may not yet have a redirect URI at state-creation time.

Columns:
  - id:               UUID primary key (server-generated)
  - organization_id:  FK → organizations.id (CASCADE)
  - user_id:          FK → users.id (CASCADE)
  - state_token:      varchar(128), unique, indexed — the CSRF token
  - redirect_uri:     varchar(512), nullable — redirect after consent
  - scopes:           json, nullable — granted OAuth scopes (audit)
  - expires_at:       timestamptz, indexed — TTL enforcement
  - used:             bool — single-use enforcement
  - created_at:       timestamptz — auto-set on insert

Revision ID: 022_google_oauth_states
Revises: 021_events_log_org_not_null
Create Date: 2026-09-25
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "022_google_oauth_states"
down_revision = "021_events_log_org_not_null"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "google_oauth_states",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "organization_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "state_token",
            sa.String(128),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "redirect_uri",
            sa.String(512),
            nullable=True,  # Google model allows NULL
        ),
        sa.Column("scopes", sa.JSON, nullable=True),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "used",
            sa.Boolean,
            nullable=False,
            server_default="false",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_google_oauth_states_org_id",
        "google_oauth_states",
        ["organization_id"],
    )
    op.create_index(
        "ix_google_oauth_states_state_token",
        "google_oauth_states",
        ["state_token"],
    )
    op.create_index(
        "ix_google_oauth_states_expires_at",
        "google_oauth_states",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_google_oauth_states_expires_at",
        table_name="google_oauth_states",
    )
    op.drop_index(
        "ix_google_oauth_states_state_token",
        table_name="google_oauth_states",
    )
    op.drop_index(
        "ix_google_oauth_states_org_id",
        table_name="google_oauth_states",
    )
    op.drop_table("google_oauth_states")
