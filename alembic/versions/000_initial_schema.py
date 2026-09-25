"""Initial baseline schema — creates the four legacy tables.

This migration reconstructs the original single-tenant schema that existed
before the multi-tenant foundation (001_multi_tenant). On the original
production database these tables were created manually or by SQLAlchemy
create_all(); no earlier Alembic migration existed for them.

Tables created:
  - leads
  - events_log
  - failed_jobs
  - schedule_config

Revision ID: 000_initial_schema
Create Date: 2026-09-25
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ENUM as PG_ENUM, UUID as PG_UUID

# revision identifiers, used by Alembic.
revision: str = "000_initial_schema"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the four legacy baseline tables."""

    # ------------------------------------------------------------------
    # 1. Create the lead_status enum type
    # ------------------------------------------------------------------
    op.execute(
        "DO $$ BEGIN"
        "  CREATE TYPE lead_status AS ENUM ("
        "    'pending', 'scheduled', 'accepted', 'tentative',"
        "    'declined', 'not_interested', 'reminded', 'error', 'completed'"
        "  );"
        " EXCEPTION WHEN duplicate_object THEN NULL;"
        " END $$"
    )

    # ------------------------------------------------------------------
    # 2. leads table
    # ------------------------------------------------------------------
    op.create_table(
        "leads",
        sa.Column(
            "id",
            PG_UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("interested", sa.String, nullable=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("company_address", sa.Text, nullable=True),
        sa.Column("phone_number", sa.String, nullable=True),
        sa.Column("direct_number", sa.String, nullable=True),
        sa.Column("courses", sa.String, nullable=True),
        sa.Column("email", sa.String, nullable=True),
        sa.Column("scheduled_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("caller_name", sa.String, nullable=True),
        sa.Column("appt_datetime_raw", sa.String, nullable=True),
        sa.Column("appt_datetime_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            PG_ENUM(
                name="lead_status",
                create_type=False,
            ),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("calendar_event_id", sa.String, nullable=True, unique=True),
        sa.Column("dedupe_key", sa.String, nullable=True),
        sa.Column("reminder_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    # Explicit unique index on dedupe_key (matches the model's __table_args__)
    op.create_index(
        "ix_leads_dedupe_key", "leads", ["dedupe_key"], unique=True
    )

    # ------------------------------------------------------------------
    # 3. events_log table
    # ------------------------------------------------------------------
    op.create_table(
        "events_log",
        sa.Column(
            "id",
            PG_UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "lead_id",
            PG_UUID(as_uuid=True),
            sa.ForeignKey("leads.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String, nullable=False),
        sa.Column("payload", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # ------------------------------------------------------------------
    # 4. failed_jobs table
    # ------------------------------------------------------------------
    op.create_table(
        "failed_jobs",
        sa.Column(
            "id",
            PG_UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("job_type", sa.String, nullable=False),
        sa.Column("payload", sa.Text, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column(
            "retry_count",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "resolved",
            sa.String,
            nullable=False,
            server_default="false",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # ------------------------------------------------------------------
    # 5. schedule_config table
    # ------------------------------------------------------------------
    op.create_table(
        "schedule_config",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "reminder_time",
            sa.String,
            nullable=False,
            server_default="08:00",
        ),
        sa.Column(
            "rsvp_poll_interval_minutes",
            sa.Integer,
            nullable=False,
            server_default="10",
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    """Drop the four legacy baseline tables (destructive — use with caution)."""
    op.drop_table("schedule_config")
    op.drop_table("failed_jobs")
    op.drop_table("events_log")
    op.drop_index("ix_leads_dedupe_key", table_name="leads")
    op.drop_table("leads")
    op.execute("DROP TYPE IF EXISTS lead_status")
