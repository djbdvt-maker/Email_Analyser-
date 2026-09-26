from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.models import AIExecutionProvenance, AuditAction, User
from app.qualification_registry import REGISTRY_VERSION, VALIDITY_RULE_VERSION
from app.schemas import AIExecutionProvenanceCreate
from app.services.analysis_run_service import get_analysis_run


def create_ai_execution(
    db: Session, *, user: User, investigation_id: str, run_id: str,
    payload: AIExecutionProvenanceCreate,
) -> AIExecutionProvenance:
    """
    Creates the immutable provenance record for one AI execution. Only
    one may exist per AnalysisRun (1:1) -- a second call for the same
    run is rejected; a retry must create a new AnalysisRun instead.
    Pins qualification_registry_version/validity_rule_version to
    whatever this backend build currently uses, so later registry
    changes never retroactively alter how an already-executed AI call
    is interpreted.
    """
    run = get_analysis_run(db, user=user, run_id=run_id, investigation_id=investigation_id)

    existing = db.query(AIExecutionProvenance).filter(
        AIExecutionProvenance.analysis_run_id == run.id
    ).one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An AI execution already exists for this analysis run. Retry via a new AnalysisRun.",
        )

    execution = AIExecutionProvenance(
        analysis_run_id=run.id,
        model_identifier=payload.model_identifier,
        model_version_or_digest=payload.model_version_or_digest,
        prompt_schema_version=payload.prompt_schema_version,
        qualification_registry_version=REGISTRY_VERSION,
        validity_rule_version=VALIDITY_RULE_VERSION,
        deterministic_context_snapshot_hash=payload.deterministic_context_snapshot_hash,
        ai_generation_parameters=payload.ai_generation_parameters,
    )
    db.add(execution)
    db.flush()

    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.AI_EXECUTION_CREATED,
        investigation_id=investigation_id,
        actor_user_id=user.id,
        metadata={
            "ai_execution_id": execution.id,
            "model_identifier": execution.model_identifier,
            "qualification_registry_version": execution.qualification_registry_version,
        },
    )
    db.commit()
    db.refresh(execution)
    return execution


def get_ai_execution(db: Session, *, user: User, investigation_id: str, run_id: str) -> AIExecutionProvenance:
    run = get_analysis_run(db, user=user, run_id=run_id, investigation_id=investigation_id)
    execution = db.query(AIExecutionProvenance).filter(
        AIExecutionProvenance.analysis_run_id == run.id
    ).one_or_none()
    if execution is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No AI execution for this run")
    return execution
