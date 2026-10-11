"""Action drafts table for bot-initiated actions as drafts
(Invariant 7: Never an automatic irreversible action)

Revision ID: 0005_action_drafts
Revises: 0004_feedback_enforcement
Create Date: 2026-10-11
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0005_action_drafts"
down_revision: Union[str, None] = "0004_feedback_enforcement"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "action_drafts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("investigation_id", sa.String(36), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("action_type", sa.String(64), nullable=False),
        sa.Column("proposed_payload", sa.JSON(), nullable=False),
        sa.Column(
            "status",
            sa.Enum("PENDING_CONFIRMATION", "CONFIRMED", "REJECTED", "CANCELLED", name="actiondraftstatus"),
            nullable=False,
            server_default="PENDING_CONFIRMATION",
        ),
        sa.Column("created_by_bot", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by_actor", sa.String(128), nullable=False, server_default="botchain"),
        sa.Column("created_by_user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("confirmed_by_user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("execution_result", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("action_drafts")
