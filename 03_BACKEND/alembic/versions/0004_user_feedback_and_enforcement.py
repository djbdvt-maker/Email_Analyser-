"""User feedback and enforcement actions tables

Revision ID: 0004_feedback_enforcement
Revises: 0003_run_scoped_finding_dedup
Create Date: 2026-09-18

This migration:
1. Creates the user_feedbacks table for storing user-guided feedback
   (SPAM_REPORTED, PHISHING_REPORTED, ANALYSIS_DISPUTED) triggering re-analysis runs.
2. Creates the enforcement_actions table for provider-neutral threat response tracking
   (REQUESTED -> AUTHORIZED -> EXECUTED / FAILED / REJECTED).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_feedback_enforcement"
down_revision: Union[str, None] = "0003_run_scoped_finding_dedup"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create user_feedbacks table
    op.create_table(
        "user_feedbacks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("investigation_id", sa.String(36), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("source_analysis_run_id", sa.String(36), sa.ForeignKey("analysis_runs.id"), nullable=False),
        sa.Column("actor_user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("feedback_type", sa.String(64), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("resulting_analysis_run_id", sa.String(36), sa.ForeignKey("analysis_runs.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. Create enforcement_actions table
    op.create_table(
        "enforcement_actions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("investigation_id", sa.String(36), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column(
            "action_type",
            sa.Enum("BLOCK_SENDER", "BLOCK_DOMAIN", "BLOCK_IP", "QUARANTINE", name="enforcementactiontype"),
            nullable=False,
        ),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column(
            "status",
            sa.Enum("REQUESTED", "AUTHORIZED", "EXECUTED", "FAILED", "REJECTED", name="enforcementstatus"),
            nullable=False,
            server_default="REQUESTED",
        ),
        sa.Column("provider", sa.String(128), nullable=False, server_default="mock_local_provider"),
        sa.Column("is_demo", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("requested_by_user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("authorized_by_user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("executed_by_user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("execution_details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("enforcement_actions")
    op.drop_table("user_feedbacks")
