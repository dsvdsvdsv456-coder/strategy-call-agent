"""add org integration last error

Revision ID: c86767462466
Revises: aeeb005a9e52
Create Date: 2026-09-25

Add the missing last_error column expected by the OrgIntegration model.
"""

from typing import Sequence, Union

from alembic import op


revision: str = "c86767462466"
down_revision: Union[str, Sequence[str], None] = "aeeb005a9e52"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add last_error when it is missing."""
    op.execute(
        """
        ALTER TABLE org_integrations
        ADD COLUMN IF NOT EXISTS last_error TEXT;
        """
    )


def downgrade() -> None:
    """Remove last_error."""
    op.execute(
        """
        ALTER TABLE org_integrations
        DROP COLUMN IF EXISTS last_error;
        """
    )