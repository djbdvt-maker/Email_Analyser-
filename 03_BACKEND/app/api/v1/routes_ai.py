from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import AIExecutionProvenanceCreate, AIExecutionProvenanceOut, AICandidateCreate, AICandidateOut
from app.security import get_current_user
from app.services import ai_execution_service, trust_boundary_service

router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/analysis-runs/{run_id}",
    tags=["ai-trust-boundary"],
)


@router.post("/ai-execution", response_model=AIExecutionProvenanceOut, status_code=201)
def create_ai_execution(
    investigation_id: str,
    run_id: str,
    body: AIExecutionProvenanceCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Records the immutable provenance of one AI execution for this
    AnalysisRun. Exactly one may exist per run (409 on a second call);
    a retry must create a new AnalysisRun instead of mutating this one.
    """
    return ai_execution_service.create_ai_execution(
        db, user=user, investigation_id=investigation_id, run_id=run_id, payload=body
    )


@router.get("/ai-execution", response_model=AIExecutionProvenanceOut)
def get_ai_execution(
    investigation_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return ai_execution_service.get_ai_execution(
        db, user=user, investigation_id=investigation_id, run_id=run_id
    )


@router.post("/ai-candidates", response_model=AICandidateOut, status_code=201)
def submit_ai_candidate(
    investigation_id: str,
    run_id: str,
    body: AICandidateCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    THE only entry point for AI-derived semantic output. Requires an
    AI execution to already exist for this run. Submitting here never
    directly creates a Score, a floor, a severity, or a Fact -- at
    most, if every validation stage passes, it creates or merges one
    Finding with a strength computed deterministically by the backend.
    """
    return trust_boundary_service.submit_ai_candidate(
        db, user=user, investigation_id=investigation_id, run_id=run_id, payload=body
    )


@router.get("/ai-candidates", response_model=list[AICandidateOut])
def list_ai_candidates(
    investigation_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from app.models import AICandidate
    from app.services.analysis_run_service import get_analysis_run

    run = get_analysis_run(db, user=user, run_id=run_id, investigation_id=investigation_id)
    return db.query(AICandidate).filter(AICandidate.analysis_run_id == run.id).all()
