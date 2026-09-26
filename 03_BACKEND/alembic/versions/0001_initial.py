"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-09-12

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    op.create_table(
        "organizations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.Enum("ADMIN", "ANALYST", "VIEWER", name="userrole"), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "investigations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "AWAITING_ANALYSIS", "ANALYZED", "UNDER_REVIEW", "CONFIRMED",
                "FALSE_POSITIVE", "ESCALATED", "CLOSED",
                name="investigationstatus",
            ),
            nullable=False,
        ),
        sa.Column("current_analysis_run_id", sa.String(36), nullable=True),
        sa.Column("created_by_user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "analysis_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "QUEUED", "PARSING", "ANALYZING", "SCORING", "COMPLETED", "FAILED", "CANCELLED",
                name="analysisrunstatus",
            ),
            nullable=False,
        ),
        sa.Column("failure_reason", sa.Text, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Deferred FK: investigations.current_analysis_run_id -> analysis_runs.id
    op.create_foreign_key(
        "fk_investigations_current_run", "investigations", "analysis_runs",
        ["current_analysis_run_id"], ["id"],
    )

    op.create_table(
        "artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("storage_path", sa.String(1024), nullable=False),
        sa.Column("original_filename", sa.String(512), nullable=False),
        sa.Column("mime_type", sa.String(255), nullable=False),
        sa.Column("size_bytes", sa.Integer, nullable=False),
        sa.Column("original_artifact_sha256", sa.String(64), nullable=False),
        sa.Column("original_artifact_md5", sa.String(32), nullable=True),
        sa.Column("export_bundle_sha256", sa.String(64), nullable=True),
        sa.Column("exported_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "facts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("analysis_run_id", sa.String(36), sa.ForeignKey("analysis_runs.id"), nullable=False),
        sa.Column("fact_type", sa.String(128), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.Column("produced_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("qualification_code", sa.String(128), nullable=False),
        sa.Column("qualification_version", sa.String(32), nullable=False),
        sa.Column("strength", sa.String(32), nullable=False),
        sa.Column("normalized_subject_or_target", sa.String(512), nullable=False),
        sa.Column("claim_signature", sa.String(128), nullable=False),
        sa.Column("supporting_fact_ids", sa.JSON, nullable=False),
        sa.Column("supporting_text", sa.Text, nullable=False),
        sa.Column("produced_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "investigation_id", "category", "qualification_code",
            "claim_signature", "normalized_subject_or_target",
            name="uq_finding_dedup_key",
        ),
    )

    op.create_table(
        "score_conclusions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("analysis_run_id", sa.String(36), sa.ForeignKey("analysis_runs.id"), nullable=False, unique=True),
        sa.Column("total_score", sa.Integer, nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("triggered_floor_codes", sa.JSON, nullable=False),
        sa.Column("conclusion_text", sa.Text, nullable=False),
        sa.Column("provenance", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("investigation_id", sa.String(36), nullable=True),
        sa.Column("actor_user_id", sa.String(36), nullable=True),
        sa.Column(
            "action",
            sa.Enum(
                "INVESTIGATION_CREATED", "INVESTIGATION_STATUS_CHANGED", "INVESTIGATION_REOPENED",
                "ANALYSIS_RUN_CREATED", "ANALYSIS_RUN_STATUS_CHANGED", "ARTIFACT_INGESTED",
                "EVIDENCE_EXPORTED", "FINDING_PERSISTED", "FINDING_MERGED", "SCORE_CONCLUSION_PERSISTED",
                name="auditaction",
            ),
            nullable=False,
        ),
        sa.Column("metadata_json", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    if is_postgres:
        # Defense-in-depth: reject UPDATE/DELETE against audit_events at
        # the database layer, independent of application code discipline.
        op.execute(
            """
            CREATE OR REPLACE FUNCTION reject_audit_event_mutation()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION 'audit_events is append-only: % not permitted', TG_OP;
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        op.execute(
            """
            CREATE TRIGGER audit_events_no_update
            BEFORE UPDATE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();
            """
        )
        op.execute(
            """
            CREATE TRIGGER audit_events_no_delete
            BEFORE DELETE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();
            """
        )


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    if is_postgres:
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events;")
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;")
        op.execute("DROP FUNCTION IF EXISTS reject_audit_event_mutation;")

    op.drop_table("audit_events")
    op.drop_table("score_conclusions")
    op.drop_table("findings")
    op.drop_table("facts")
    op.drop_table("artifacts")
    op.drop_constraint("fk_investigations_current_run", "investigations", type_="foreignkey")
    op.drop_table("analysis_runs")
    op.drop_table("investigations")
    op.drop_table("users")
    op.drop_table("organizations")

    if is_postgres:
        op.execute("DROP TYPE IF EXISTS auditaction;")
        op.execute("DROP TYPE IF EXISTS analysisrunstatus;")
        op.execute("DROP TYPE IF EXISTS investigationstatus;")
        op.execute("DROP TYPE IF EXISTS userrole;")
