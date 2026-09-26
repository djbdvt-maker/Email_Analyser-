"""Run-scoped finding deduplication constraint

Revision ID: 0003_run_scoped_finding_dedup
Revises: 0002_v4_trust_boundary
Create Date: 2026-09-13

This migration:
1. Adds findings.analysis_run_id (FK to analysis_runs.id) -- required
   for the run-scoped deduplication constraint that follows.
2. Drops the old investigation-scoped dedup constraint.
3. Creates the new run-scoped dedup constraint including analysis_run_id.
4. Makes analysis_run_id NOT NULL. For a fresh database this is trivially
   safe (no rows exist). For an existing database with NULL-run findings,
   this migration will FAIL with a clear NOT NULL violation rather than
   silently inventing ownership -- this is intentional. Legacy NULL-run
   findings must be resolved explicitly before upgrading.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003_run_scoped_finding_dedup"
down_revision: Union[str, None] = "0002_v4_trust_boundary"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Step 1: Add the analysis_run_id column (nullable initially for
    # existing-row safety check -- will be tightened to NOT NULL below).
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(
            sa.Column("analysis_run_id", sa.String(36), nullable=True),
        )

    # Step 2: For an existing database, verify no NULL-run findings exist.
    # If any do, the ALTER COLUMN NOT NULL below will fail with a clear
    # database error. We do NOT backfill or delete them.

    # Step 3: Add the foreign key constraint.
    with op.batch_alter_table("findings") as batch_op:
        batch_op.create_foreign_key(
            "fk_findings_analysis_run_id",
            "analysis_runs",
            ["analysis_run_id"],
            ["id"],
        )

    # Step 4: Make analysis_run_id NOT NULL.
    # On a fresh database (no findings rows), this is a no-op constraint.
    # On an existing database with NULL values, this will raise a clear
    # database error rather than silently proceeding.
    with op.batch_alter_table("findings") as batch_op:
        batch_op.alter_column("analysis_run_id", nullable=False)

    # Step 5: Drop old dedup constraint and create run-scoped one.
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_constraint("uq_finding_dedup_key", type_="unique")
        batch_op.create_unique_constraint(
            "uq_finding_run_dedup_key",
            [
                "investigation_id",
                "analysis_run_id",
                "category",
                "qualification_code",
                "claim_signature",
                "normalized_subject_or_target",
            ],
        )


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_constraint("uq_finding_run_dedup_key", type_="unique")
        batch_op.create_unique_constraint(
            "uq_finding_dedup_key",
            [
                "investigation_id",
                "category",
                "qualification_code",
                "claim_signature",
                "normalized_subject_or_target",
            ],
        )
        batch_op.drop_constraint("fk_findings_analysis_run_id", type_="foreignkey")
        batch_op.drop_column("analysis_run_id")
