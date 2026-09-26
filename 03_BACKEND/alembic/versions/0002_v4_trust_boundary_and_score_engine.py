"""V4: AI trust boundary tables + Score Engine schema changes

Revision ID: 0002_v4_trust_boundary
Revises: 0001_initial
Create Date: 2026-09-12

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_v4_trust_boundary"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    if is_postgres:
        # Postgres enums are closed types; new AuditAction members must
        # be added explicitly. ALTER TYPE ... ADD VALUE cannot run
        # inside the same transaction as other DDL on some PG versions,
        # so these are issued with autocommit via execution_options.
        with op.get_context().autocommit_block():
            for value in ("AI_EXECUTION_CREATED", "AI_CANDIDATE_ACCEPTED", "AI_CANDIDATE_REJECTED"):
                op.execute(f"ALTER TYPE auditaction ADD VALUE IF NOT EXISTS '{value}'")

    op.create_table(
        "ai_execution_provenances",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("analysis_run_id", sa.String(36), sa.ForeignKey("analysis_runs.id"), nullable=False, unique=True),
        sa.Column("model_identifier", sa.String(255), nullable=False),
        sa.Column("model_version_or_digest", sa.String(255), nullable=False),
        sa.Column("prompt_schema_version", sa.String(64), nullable=False),
        sa.Column("qualification_registry_version", sa.String(64), nullable=False),
        sa.Column("validity_rule_version", sa.String(64), nullable=False),
        sa.Column("deterministic_context_snapshot_hash", sa.String(64), nullable=False),
        sa.Column("ai_generation_parameters", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "ai_candidates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("analysis_run_id", sa.String(36), sa.ForeignKey("analysis_runs.id"), nullable=False),
        sa.Column("ai_execution_id", sa.String(36), sa.ForeignKey("ai_execution_provenances.id"), nullable=False),
        sa.Column("qualification_code", sa.String(128), nullable=False),
        sa.Column("claim_signature", sa.String(128), nullable=False),
        sa.Column("supporting_text", sa.Text, nullable=False),
        sa.Column("source_fact_id", sa.String(36), sa.ForeignKey("facts.id"), nullable=False),
        sa.Column("model_suggested_strength", sa.String(32), nullable=True),
        sa.Column("model_confidence", sa.String(32), nullable=True),
        sa.Column("produced_by", sa.String(128), nullable=False),
        sa.Column("status", sa.Enum("ACCEPTED", "REJECTED", name="aicandidatestatus"), nullable=False),
        sa.Column("rejection_stage", sa.String(64), nullable=True),
        sa.Column("rejection_reason", sa.Text, nullable=True),
        sa.Column("resulting_finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.add_column(
        "score_conclusions",
        sa.Column("category_breakdown", sa.JSON, nullable=True),
    )
    # Not backfilling existing rows with a JSON server_default here to
    # avoid Postgres type-cast pitfalls with a bare string literal
    # default on a JSON column. In practice this migration runs before
    # any ScoreConclusion rows exist under the new (caller-cannot-
    # supply-score) contract, so there is nothing to backfill. If rows
    # somehow already exist, backfill them explicitly before relying on
    # this column being non-null; the ORM model expects it non-null for
    # every row the application itself creates going forward.


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    op.drop_column("score_conclusions", "category_breakdown")
    op.drop_table("ai_candidates")
    op.drop_table("ai_execution_provenances")

    if is_postgres:
        op.execute("DROP TYPE IF EXISTS aicandidatestatus;")
        # Note: Postgres does not support removing values from an enum
        # type; AI_EXECUTION_CREATED / AI_CANDIDATE_ACCEPTED /
        # AI_CANDIDATE_REJECTED will remain valid (but unused) members
        # of auditaction after downgrade. This is a known, documented
        # limitation of Postgres enum types, not an oversight.
