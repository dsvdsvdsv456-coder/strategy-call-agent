"""Create invitation_codes table.

The ``invitation_codes`` table stores one-time invitation codes for
invite-only account creation.  Each code is cryptographically random,
hashed with bcrypt before storage, and can only be redeemed once.

Lifecycle:
  - UNUSED  → code generated, awaiting redemption
  - USED    → code successfully redeemed during registration
  - EXPIRED → code past its optional expiration timestamp
  - REVOKED → code manually revoked by an admin

Columns:
  - id:              UUID primary key (server-generated)
  - code_hash:       varchar(255), unique, indexed — bcrypt hash of the code
  - code_prefix:     varchar(20) — first segment for admin display (SCA-XXXX)
  - status:          invitation_status enum — unused | used | expired | revoked
  - label:           varchar(200), nullable — optional customer/org label
  - email:           varchar(320), nullable — intended recipient email
  - expires_at:      timestamptz, nullable — optional expiration
  - used_at:         timestamptz, nullable — when code was redeemed
  - used_by_user_id: FK → users.id, nullable — user who redeemed
  - revoked_at:      timestamptz, nullable — when code was revoked
  - created_by_user_id: FK → users.id — who generated this code
  - organization_id: FK → organizations.id — scoping (platform-level codes
                       belong to the creating user's org)
  - created_at:      timestamptz — auto-set on insert
  - updated_at:      timestamptz — auto-set on insert/update

Revision ID: 023_invitation_codes
Revises: c86767462466_add_org_integration_last_error
Create Date: 2026-09-25
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "023_invitation_codes"
down_revision = "c86767462466"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create the invitation_status enum type (idempotent).
    op.execute(
        "DO $$ BEGIN "
        "CREATE TYPE invitation_status AS ENUM "
        "('unused','used','expired','revoked'); "
        "EXCEPTION WHEN duplicate_object THEN NULL; "
        "END $$"
    )

    # Create the invitation_codes table using raw SQL.
    # We use raw SQL to avoid SQLAlchemy Enum DDL conflicts when the
    # env.py target_metadata already registers the same enum type.
    op.execute("""
        CREATE TABLE IF NOT EXISTS invitation_codes (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            code_hash       VARCHAR(255) NOT NULL UNIQUE,
            code_prefix     VARCHAR(20) NOT NULL,
            status          invitation_status NOT NULL DEFAULT 'unused',
            label           VARCHAR(200),
            email           VARCHAR(320),
            expires_at      TIMESTAMPTZ,
            used_at         TIMESTAMPTZ,
            used_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            revoked_at      TIMESTAMPTZ,
            created_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)

    # Indexes
    op.create_index(
        "ix_invitation_codes_org_id",
        "invitation_codes",
        ["organization_id"],
    )
    op.create_index(
        "ix_invitation_codes_status",
        "invitation_codes",
        ["status"],
    )
    op.create_index(
        "ix_invitation_codes_created_by",
        "invitation_codes",
        ["created_by_user_id"],
    )


def downgrade() -> None:
    op.drop_table("invitation_codes")
    op.execute("DROP TYPE IF EXISTS invitation_status")
