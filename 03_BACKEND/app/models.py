"""
ORM models.

V4 scope note: Facts are deterministic observations only. AICandidate
rows are untrusted model proposals that must pass the validation
pipeline in app/services/trust_boundary_service.py before a Finding is
ever created or merged. FindingCandidate is NOT a persisted table --
it is a transient, in-memory object (see
app/services/trust_boundary_service.py) representing "passed
validation but not yet the final Finding row"; keeping it
non-persisted avoids conflating it with either AICandidate or Finding
in the schema. The backend now owns the deterministic Score Engine
(app/services/score_engine.py) directly -- it is no longer an external
interface.
"""
import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, DateTime, ForeignKey, Enum as SAEnum, JSON,
    UniqueConstraint, Integer, Boolean, Text,
)
from sqlalchemy.orm import relationship

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Enums
# --------------------------------------------------------------------------

class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"
    USER = "USER"


class InvestigationStatus(str, enum.Enum):
    AWAITING_ANALYSIS = "AWAITING_ANALYSIS"
    UNDER_REVIEW = "UNDER_REVIEW"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ESCALATED = "ESCALATED"
    CLOSED = "CLOSED"
    # NOTE: there is intentionally no REOPENED status. "Reopen" is an
    # action, implemented in services/investigation_service.py, that
    # transitions an investigation back to UNDER_REVIEW.


class AnalysisRunStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    PARSING = "PARSING"
    ANALYZING = "ANALYZING"
    SCORING = "SCORING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AuditAction(str, enum.Enum):
    INVESTIGATION_CREATED = "INVESTIGATION_CREATED"
    INVESTIGATION_STATUS_CHANGED = "INVESTIGATION_STATUS_CHANGED"
    INVESTIGATION_REOPENED = "INVESTIGATION_REOPENED"
    NOTE_ADDED = "NOTE_ADDED"
    ANALYSIS_RUN_CREATED = "ANALYSIS_RUN_CREATED"
    ANALYSIS_RUN_STATUS_CHANGED = "ANALYSIS_RUN_STATUS_CHANGED"
    ARTIFACT_INGESTED = "ARTIFACT_INGESTED"
    EVIDENCE_EXPORTED = "EVIDENCE_EXPORTED"
    FINDING_PERSISTED = "FINDING_PERSISTED"
    FINDING_MERGED = "FINDING_MERGED"
    SCORE_CONCLUSION_PERSISTED = "SCORE_CONCLUSION_PERSISTED"
    AI_EXECUTION_CREATED = "AI_EXECUTION_CREATED"
    AI_CANDIDATE_ACCEPTED = "AI_CANDIDATE_ACCEPTED"
    AI_CANDIDATE_REJECTED = "AI_CANDIDATE_REJECTED"
    USER_FEEDBACK_SUBMITTED = "USER_FEEDBACK_SUBMITTED"
    REANALYSIS_REQUESTED = "REANALYSIS_REQUESTED"
    ENFORCEMENT_REQUESTED = "ENFORCEMENT_REQUESTED"
    ENFORCEMENT_AUTHORIZED = "ENFORCEMENT_AUTHORIZED"
    ENFORCEMENT_EXECUTED = "ENFORCEMENT_EXECUTED"
    ENFORCEMENT_FAILED = "ENFORCEMENT_FAILED"
    ENFORCEMENT_REJECTED = "ENFORCEMENT_REJECTED"
    LAYA_PRESCREEN_COMPLETED = "LAYA_PRESCREEN_COMPLETED"


class AICandidateStatus(str, enum.Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


# --------------------------------------------------------------------------
# Tenancy
# --------------------------------------------------------------------------

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    users = relationship("User", back_populates="organization")
    investigations = relationship("Investigation", back_populates="organization")


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    email = Column(String(255), nullable=False, unique=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(SAEnum(UserRole), nullable=False, default=UserRole.ANALYST)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    organization = relationship("Organization", back_populates="users")


# --------------------------------------------------------------------------
# Investigation / AnalysisRun
# --------------------------------------------------------------------------

class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String(36), primary_key=True, default=_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    title = Column(String(255), nullable=False)
    status = Column(SAEnum(InvestigationStatus), nullable=False,
                     default=InvestigationStatus.AWAITING_ANALYSIS)

    # Points at the latest successfully COMPLETED AnalysisRun only.
    # Failed/cancelled runs must never populate this column -- enforced
    # in services/analysis_run_service.py, not just by convention.
    # use_alter breaks the circular FK dependency between investigations
    # and analysis_runs (each references the other) so that both
    # Base.metadata.create_all() in tests and Alembic's own dependency
    # ordering can create these two tables without a
    # CircularDependencyError. The hand-written migration achieves the
    # same effect explicitly via a deferred op.create_foreign_key call.
    current_analysis_run_id = Column(
        String(36),
        ForeignKey("analysis_runs.id", use_alter=True, name="fk_investigations_current_run"),
        nullable=True,
    )

    created_by_user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)

    organization = relationship("Organization", back_populates="investigations")
    analysis_runs = relationship(
        "AnalysisRun", back_populates="investigation",
        foreign_keys="AnalysisRun.investigation_id",
    )
    artifacts = relationship("Artifact", back_populates="investigation")
    facts = relationship("Fact", back_populates="investigation")
    findings = relationship("Finding", back_populates="investigation")
    user_feedbacks = relationship("UserFeedback", back_populates="investigation")
    enforcement_actions = relationship("EnforcementAction", back_populates="investigation")



class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id = Column(String(36), primary_key=True, default=_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)
    artifact_id = Column(String(36), ForeignKey("artifacts.id"), nullable=False)
    status = Column(SAEnum(AnalysisRunStatus), nullable=False, default=AnalysisRunStatus.QUEUED)
    failure_reason = Column(Text, nullable=True)

    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)

    investigation = relationship(
        "Investigation", back_populates="analysis_runs",
        foreign_keys=[investigation_id],
    )


# --------------------------------------------------------------------------
# Evidence / Artifacts
# --------------------------------------------------------------------------

class Artifact(Base):
    """
    Immutable original-evidence record for an investigation.

    The prototype in-memory Evidence(content=...) abstraction from the
    earlier package is replaced here with a real, persisted contract.
    The original bytes are written once to durable storage (see
    services/evidence_service.py) and never rewritten afterward.
    """
    __tablename__ = "artifacts"

    id = Column(String(36), primary_key=True, default=_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)

    storage_path = Column(String(1024), nullable=False)
    original_filename = Column(String(512), nullable=False)
    mime_type = Column(String(255), nullable=False)
    size_bytes = Column(Integer, nullable=False)

    original_artifact_sha256 = Column(String(64), nullable=False)
    original_artifact_md5 = Column(String(32), nullable=True)

    # Populated only when an explicit export operation has produced a
    # bundle. Never fabricated when no export has happened.
    export_bundle_sha256 = Column(String(64), nullable=True)
    exported_at = Column(DateTime(timezone=True), nullable=True)
    ingestion_source = Column(String(128), nullable=True)
    provider_message_id = Column(String(512), nullable=True)

    ingested_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    investigation = relationship("Investigation", back_populates="artifacts")


# --------------------------------------------------------------------------
# Facts / Findings
# --------------------------------------------------------------------------

class Fact(Base):
    """
    A grounded, deterministic observation produced upstream by
    hopzero-forensics (or a validated AI candidate that has already
    passed the trust boundary). The backend persists facts as-is; it
    does not derive or reinterpret them.
    """
    __tablename__ = "facts"

    id = Column(String(36), primary_key=True, default=_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id"), nullable=False)

    fact_type = Column(String(128), nullable=False)
    payload = Column(JSON, nullable=False, default=dict)
    produced_by = Column(String(128), nullable=False)

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    investigation = relationship("Investigation", back_populates="facts")


class Finding(Base):
    """
    Canonical Finding contract (locked architecture). `strength` is set
    ONLY by app/services/trust_boundary_service.py (for AI-derived
    candidates, via deterministic strength rules) or by a trusted
    deterministic producer submitting directly (see
    finding_service.persist_finding's produced_by allow-list check) --
    never by an arbitrary caller-supplied value taken at face value.
    """
    __tablename__ = "findings"
    __table_args__ = (
        # Dedup identity: category + qualification_code + claim_signature
        # + normalized target, scoped per investigation and analysis_run.
        UniqueConstraint(
            "investigation_id", "analysis_run_id", "category", "qualification_code",
            "claim_signature", "normalized_subject_or_target",
            name="uq_finding_run_dedup_key",
        ),
    )

    id = Column(String(36), primary_key=True, default=_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id"), nullable=False)

    category = Column(String(64), nullable=False)
    qualification_code = Column(String(128), nullable=False)
    qualification_version = Column(String(32), nullable=False)
    strength = Column(String(32), nullable=False)  # Negligible/Weak/Moderate/Strong
    mitre_id = Column(String(32), nullable=True)   # MITRE ATT&CK mapping

    normalized_subject_or_target = Column(String(512), nullable=False, default="")
    claim_signature = Column(String(128), nullable=False)

    supporting_fact_ids = Column(JSON, nullable=False, default=list)
    supporting_text = Column(Text, nullable=False)
    produced_by = Column(String(128), nullable=False)

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)

    investigation = relationship("Investigation", back_populates="findings")


# --------------------------------------------------------------------------
# AI trust boundary
# --------------------------------------------------------------------------

class AIExecutionProvenance(Base):
    """
    Immutable, 1:1-per-AnalysisRun record of one AI execution's
    provenance. No update/delete code path exists for this table --
    a retry is a new AnalysisRun (and therefore a new
    AIExecutionProvenance), never a mutation of this row.
    """
    __tablename__ = "ai_execution_provenances"

    id = Column(String(36), primary_key=True, default=_uuid)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id"), nullable=False, unique=True)

    model_identifier = Column(String(255), nullable=False)
    model_version_or_digest = Column(String(255), nullable=False)
    prompt_schema_version = Column(String(64), nullable=False)
    qualification_registry_version = Column(String(64), nullable=False)
    validity_rule_version = Column(String(64), nullable=False)
    deterministic_context_snapshot_hash = Column(String(128), nullable=False)
    ai_generation_parameters = Column(JSON, nullable=False, default=dict)

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)


class AICandidate(Base):
    """
    An untrusted model proposal. Persisted regardless of outcome (both
    ACCEPTED and REJECTED) for audit purposes. Only on ACCEPTED does
    resulting_finding_id point at a real Finding -- a REJECTED
    AICandidate NEVER creates or merges into a Finding, and is never
    consumed by the Score Engine or the floor engine.

    model_suggested_strength / model_confidence are telemetry columns
    only. No code path anywhere in this backend reads them to set
    Finding.strength, Score, Severity, or a floor.
    """
    __tablename__ = "ai_candidates"

    id = Column(String(36), primary_key=True, default=_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id"), nullable=False)
    ai_execution_id = Column(String(36), ForeignKey("ai_execution_provenances.id"), nullable=False)

    qualification_code = Column(String(128), nullable=False)
    claim_signature = Column(String(128), nullable=False)
    supporting_text = Column(Text, nullable=False)
    source_fact_id = Column(String(36), ForeignKey("facts.id"), nullable=False)

    model_suggested_strength = Column(String(32), nullable=True)  # telemetry only
    model_confidence = Column(String(32), nullable=True)  # telemetry only
    produced_by = Column(String(128), nullable=False)

    status = Column(SAEnum(AICandidateStatus), nullable=False)
    rejection_stage = Column(String(64), nullable=True)
    rejection_reason = Column(Text, nullable=True)
    resulting_finding_id = Column(String(36), ForeignKey("findings.id"), nullable=True)

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)


# --------------------------------------------------------------------------
# Score
class ScoreConclusion(Base):
    """
    Persisted, immutable output of the backend's own deterministic
    Score Engine (app/services/score_engine.py) for one AnalysisRun.
    Callers cannot supply total_score/severity/triggered_floor_codes --
    see app/services/score_engine_service.py, which computes every
    field here from validated Finding rows only.
    """
    __tablename__ = "score_conclusions"

    id = Column(String(36), primary_key=True, default=_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id"), nullable=False, unique=True)

    total_score = Column(Integer, nullable=False)
    severity = Column(String(32), nullable=False)
    verdict = Column(String(64), nullable=True)
    one_line_explanation = Column(Text, nullable=True)
    why_explanation = Column(Text, nullable=True)
    category_breakdown = Column(JSON, nullable=False, default=dict)
    triggered_floor_codes = Column(JSON, nullable=False, default=list)
    conclusion_text = Column(Text, nullable=False)
    provenance = Column(JSON, nullable=False, default=dict)

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)


# --------------------------------------------------------------------------

class AuditEvent(Base):
    """
    Append-only audit trail. No route or service in this codebase
    issues an UPDATE or DELETE against this table; a PostgreSQL-side
    trigger (see alembic/versions) additionally rejects such statements
    at the database layer for defense in depth.
    """
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=True)
    actor_user_id = Column(String(36), ForeignKey("users.id"), nullable=True)

    action = Column(SAEnum(AuditAction), nullable=False)
    metadata_json = Column(JSON, nullable=False, default=dict)

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)


# --------------------------------------------------------------------------
# User Feedback & Threat Response (Enforcement)
# --------------------------------------------------------------------------

class FeedbackType(str, enum.Enum):
    SPAM_REPORTED = "SPAM_REPORTED"
    PHISHING_REPORTED = "PHISHING_REPORTED"
    ANALYSIS_DISPUTED = "ANALYSIS_DISPUTED"


class UserFeedback(Base):
    """
    Persisted user feedback entity.
    Feedback is an input to investigation processing, NOT a verdict.
    A feedback event triggers a new AnalysisRun for forensic re-analysis;
    it never mutates or overwrites the original AnalysisRun or score.
    """
    __tablename__ = "user_feedbacks"

    id = Column(String(36), primary_key=True, default=_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)
    source_analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id"), nullable=False)
    actor_user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    feedback_type = Column(String(64), nullable=False)  # SPAM_REPORTED, PHISHING_REPORTED, ANALYSIS_DISPUTED
    note = Column(Text, nullable=True)
    resulting_analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id"), nullable=True)

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    organization = relationship("Organization")
    investigation = relationship("Investigation")
    source_run = relationship("AnalysisRun", foreign_keys=[source_analysis_run_id])
    resulting_run = relationship("AnalysisRun", foreign_keys=[resulting_analysis_run_id])
    actor = relationship("User")


class EnforcementActionType(str, enum.Enum):
    BLOCK_SENDER = "BLOCK_SENDER"
    BLOCK_DOMAIN = "BLOCK_DOMAIN"
    BLOCK_IP = "BLOCK_IP"
    QUARANTINE = "QUARANTINE"


class EnforcementStatus(str, enum.Enum):
    REQUESTED = "REQUESTED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"


class EnforcementAction(Base):
    """
    Provider-neutral enforcement action record.
    Tracks state through explicit lifecycle:
    REQUESTED -> AUTHORIZED -> EXECUTED (or FAILED / REJECTED).
    Clearly identifies local demo execution from real external mail providers.
    """
    __tablename__ = "enforcement_actions"

    id = Column(String(36), primary_key=True, default=_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)
    action_type = Column(SAEnum(EnforcementActionType), nullable=False)
    target = Column(String(512), nullable=False)  # Normalized, grounded target
    status = Column(SAEnum(EnforcementStatus), nullable=False, default=EnforcementStatus.REQUESTED)
    provider = Column(String(128), nullable=False, default="mock_local_provider")
    is_demo = Column(Boolean, nullable=False, default=True)

    requested_by_user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    authorized_by_user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    executed_by_user_id = Column(String(36), ForeignKey("users.id"), nullable=True)

    rejection_reason = Column(Text, nullable=True)
    failure_reason = Column(Text, nullable=True)
    execution_details = Column(JSON, nullable=False, default=dict)

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)

    organization = relationship("Organization")
    investigation = relationship("Investigation")
    requested_by = relationship("User", foreign_keys=[requested_by_user_id])
    authorized_by = relationship("User", foreign_keys=[authorized_by_user_id])
    executed_by = relationship("User", foreign_keys=[executed_by_user_id])

