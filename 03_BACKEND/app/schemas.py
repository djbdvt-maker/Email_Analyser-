from datetime import datetime
from typing import Optional, List, Any

from pydantic import BaseModel, ConfigDict, Field

from app.models import InvestigationStatus, AnalysisRunStatus, UserRole


# ---------------------------------------------------------------- auth ----

class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    organization_id: str
    email: str
    role: UserRole


# --------------------------------------------------------- investigation ---

class InvestigationCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)


class InvestigationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    organization_id: str
    title: str
    status: InvestigationStatus
    current_analysis_run_id: Optional[str]
    created_at: datetime
    updated_at: datetime
    score: Optional[int] = None
    severity: Optional[str] = None
    verdict: Optional[str] = None
    current_run_status: Optional[str] = None


class AnalysisResponse(BaseModel):
    investigation_id: str
    analysis_run_id: str
    status: str


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
    id: str
    organization_id: str
    investigation_id: Optional[str] = None
    actor_user_id: Optional[str] = None
    action: str
    metadata: dict = Field(alias="metadata_json", default_factory=dict)
    created_at: datetime


class InvestigationStatusUpdate(BaseModel):
    status: InvestigationStatus


class AnalystActionCreate(BaseModel):
    action: str
    note: Optional[str] = None
    falsePositiveReason: Optional[str] = None


class AnalystActionOut(BaseModel):
    actionId: str
    action: str
    actor: str
    note: Optional[str] = None
    falsePositiveReason: Optional[str] = None
    timestamp: str


# ----------------------------------------------------------- analysis run --

class AnalysisRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    investigation_id: str
    artifact_id: str
    status: AnalysisRunStatus
    failure_reason: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime


class AnalysisRunStatusUpdate(BaseModel):
    status: AnalysisRunStatus
    failure_reason: Optional[str] = None


# --------------------------------------------------------------- evidence --

class ArtifactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    investigation_id: str
    original_filename: str
    mime_type: str
    size_bytes: int
    original_artifact_sha256: str
    original_artifact_md5: Optional[str]
    export_bundle_sha256: Optional[str]
    exported_at: Optional[datetime]
    ingestion_source: Optional[str] = None
    provider_message_id: Optional[str] = None
    ingested_at: datetime


class EvidenceExportOut(BaseModel):
    artifact_id: str
    export_bundle_sha256: str
    exported_at: datetime


# ---------------------------------------------------------------- facts ----

class FactCreate(BaseModel):
    analysis_run_id: str
    fact_type: str
    payload: dict
    produced_by: str


class FactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    investigation_id: str
    analysis_run_id: str
    fact_type: str
    payload: dict
    produced_by: str
    created_at: datetime


# -------------------------------------------------------------- findings ---

class FindingCreate(BaseModel):
    """
    Input contract for a Finding submitted DIRECTLY by a trusted
    deterministic producer (e.g. hopzero-forensics), NOT by an AI
    candidate. `produced_by` must be on the deterministic allow-list
    enforced in app/services/finding_service.py -- this endpoint
    rejects anything claiming to be AI-derived; AI output must go
    through POST .../analysis-runs/{run_id}/ai-candidates instead.
    """
    category: str
    qualification_code: str
    qualification_version: str
    strength: str
    mitre_id: Optional[str] = None
    analysis_run_id: str
    normalized_subject_or_target: str = ""
    claim_signature: str
    supporting_fact_ids: List[str] = Field(default_factory=list)
    supporting_text: str
    produced_by: str


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    investigation_id: str
    analysis_run_id: str
    category: str
    qualification_code: str
    qualification_version: str
    strength: str
    mitre_id: Optional[str] = None
    normalized_subject_or_target: str
    claim_signature: str
    supporting_fact_ids: List[str]
    supporting_text: str
    produced_by: str
    created_at: datetime
    updated_at: datetime


class IngestResponse(BaseModel):
    investigation_id: str
    artifact_id: str
    analysis_run_id: Optional[str] = None
    status: str
    idempotent_replay: bool = False


# ------------------------------------------------------- AI trust boundary --

class AIExecutionProvenanceCreate(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    model_identifier: str
    model_version_or_digest: str
    prompt_schema_version: str
    deterministic_context_snapshot_hash: str
    ai_generation_parameters: dict = Field(default_factory=dict)


class AIExecutionProvenanceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())
    id: str
    analysis_run_id: str
    model_identifier: str
    model_version_or_digest: str
    prompt_schema_version: str
    qualification_registry_version: str
    validity_rule_version: str
    deterministic_context_snapshot_hash: str
    ai_generation_parameters: dict
    created_at: datetime


class AICandidateCreate(BaseModel):
    """
    The ONLY way AI-derived semantic output enters the system. This is
    deliberately untrusted: submitting this does not directly create a
    Finding, a Score, a floor, or a severity. It only ever produces a
    persisted AICandidate (ACCEPTED or REJECTED); a Finding is created
    solely as a side effect of ACCEPTED, using a strength computed
    deterministically by the backend -- never `model_suggested_strength`.
    """
    model_config = ConfigDict(protected_namespaces=())  # allow model_* field names (they're data, not pydantic internals)

    qualification_code: str
    claim_signature: str
    supporting_text: str
    source_fact_id: str
    model_suggested_strength: Optional[str] = None  # telemetry only
    model_confidence: Optional[str] = None  # telemetry only
    produced_by: str = "ai_reasoner"


class AICandidateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())
    id: str
    investigation_id: str
    analysis_run_id: str
    ai_execution_id: str
    qualification_code: str
    claim_signature: str
    supporting_text: str
    source_fact_id: str
    model_suggested_strength: Optional[str]
    model_confidence: Optional[str]
    produced_by: str
    status: str
    rejection_stage: Optional[str]
    rejection_reason: Optional[str]
    resulting_finding_id: Optional[str]
    created_at: datetime


# ---------------------------------------------------------------- score ----

class ScoreOut(BaseModel):
    """
    Output-only. There is no corresponding *In schema a caller can post
    to set these values -- see app/services/score_engine_service.py,
    which computes every field from validated Findings.
    """
    model_config = ConfigDict(from_attributes=True)
    id: str
    investigation_id: str
    analysis_run_id: str
    total_score: int
    severity: str
    verdict: Optional[str] = None
    one_line_explanation: Optional[str] = None
    why_explanation: Optional[str] = None
    category_breakdown: dict
    triggered_floor_codes: List[str]
    conclusion_text: str
    provenance: dict
    created_at: datetime


# ------------------------------------------------------------------ misc --

class ErrorResponse(BaseModel):
    error_code: str
    message: str
    details: Optional[Any] = None


# ---------------------------------------------------- user feedback & reanalysis ---

class UserFeedbackCreate(BaseModel):
    feedback_type: str = Field(..., description="SPAM_REPORTED, PHISHING_REPORTED, or ANALYSIS_DISPUTED")
    note: Optional[str] = Field(None, description="Optional analyst/user justification or context")
    source_analysis_run_id: Optional[str] = Field(None, description="Run being disputed (defaults to current)")


class UserFeedbackOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    organization_id: str
    investigation_id: str
    source_analysis_run_id: str
    actor_user_id: str
    feedback_type: str
    note: Optional[str]
    resulting_analysis_run_id: Optional[str]
    created_at: datetime


class RunComparisonOut(BaseModel):
    investigation_id: str
    run_1_id: str
    run_2_id: str
    run_1_score: Optional[int] = None
    run_2_score: Optional[int] = None
    score_delta: Optional[int] = None
    run_1_severity: Optional[str] = None
    run_2_severity: Optional[str] = None
    severity_changed: bool = False
    run_1_verdict: Optional[str] = None
    run_2_verdict: Optional[str] = None
    verdict_changed: bool = False
    new_findings: List[dict] = Field(default_factory=list)
    unchanged_findings: List[dict] = Field(default_factory=list)
    resolved_findings: List[dict] = Field(default_factory=list)
    summary: str = ""


# ------------------------------------------------------- threat enforcement ---

class GroundedOptionOut(BaseModel):
    action_type: str
    target: str
    grounded_source: str
    description: str


class EnforcementRequestCreate(BaseModel):
    action_type: str = Field(..., description="BLOCK_SENDER, BLOCK_DOMAIN, BLOCK_IP, or QUARANTINE")
    target: str = Field(..., min_length=1, max_length=512)
    context: Optional[dict] = Field(default_factory=dict)


class EnforcementRejectionCreate(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1024)


class EnforcementExecuteCreate(BaseModel):
    simulate_failure: Optional[bool] = False


class EnforcementActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    organization_id: str
    investigation_id: str
    action_type: str
    target: str
    status: str
    provider: str
    is_demo: bool
    requested_by_user_id: str
    authorized_by_user_id: Optional[str] = None
    executed_by_user_id: Optional[str] = None
    rejection_reason: Optional[str] = None
    failure_reason: Optional[str] = None
    execution_details: dict = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

