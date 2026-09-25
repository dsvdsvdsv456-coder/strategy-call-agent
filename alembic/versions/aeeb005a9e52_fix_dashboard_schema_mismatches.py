"""fix dashboard schema mismatches

Revision ID: aeeb005a9e52
Revises: 022_google_oauth_states
Create Date: 2026-09-25

Fixes:
- Convert failed_jobs.resolved from VARCHAR to BOOLEAN when necessary.
- Add missing org_integrations.connected_at column.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "aeeb005a9e52"
down_revision: Union[str, Sequence[str], None] = "022_google_oauth_states"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Apply dashboard schema fixes."""

    # Convert failed_jobs.resolved only when the existing database
    # actually has it as a character type. Some environments already
    # have the correct BOOLEAN type.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'failed_jobs'
                  AND column_name = 'resolved'
                  AND data_type = 'character varying'
            ) THEN
                ALTER TABLE failed_jobs
                ALTER COLUMN resolved DROP DEFAULT;

                ALTER TABLE failed_jobs
                ALTER COLUMN resolved TYPE BOOLEAN
                USING (
                    CASE
                        WHEN LOWER(TRIM(resolved)) IN
                            ('true', 't', '1', 'yes')
                        THEN TRUE
                        ELSE FALSE
                    END
                );

                ALTER TABLE failed_jobs
                ALTER COLUMN resolved SET DEFAULT FALSE;
            END IF;
        END
        $$;
        """
    )

    # Add connected_at only when it is missing.
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'org_integrations'
                  AND column_name = 'connected_at'
            ) THEN
                ALTER TABLE org_integrations
                ADD COLUMN connected_at TIMESTAMPTZ;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    """Revert dashboard schema fixes."""

    # Remove connected_at if this migration added it.
    op.execute(
        """
        ALTER TABLE org_integrations
        DROP COLUMN IF EXISTS connected_at;
        """
    )

    # Only convert BOOLEAN back to VARCHAR if the column currently
    # has the BOOLEAN type.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'failed_jobs'
                  AND column_name = 'resolved'
                  AND data_type = 'boolean'
            ) THEN
                ALTER TABLE failed_jobs
                ALTER COLUMN resolved DROP DEFAULT;

                ALTER TABLE failed_jobs
                ALTER COLUMN resolved TYPE VARCHAR
                USING (
                    CASE
                        WHEN resolved THEN 'true'
                        ELSE 'false'
                    END
                );

                ALTER TABLE failed_jobs
                ALTER COLUMN resolved SET DEFAULT 'false';
            END IF;
        END
        $$;
        """
    )