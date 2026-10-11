"""Add config column to analysis_runs for run reproducibility (HZ8)

Revision ID: 0006_analysis_run_config
Revises: 0005_action_drafts
Create Date: 2026-10-11
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0006_analysis_run_config"
down_revision: Union[str, None] = "0005_action_drafts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("analysis_runs", sa.Column("config", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("analysis_runs", "config")
