from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import FactCreate, FactOut, FindingCreate, FindingOut, ScoreOut
from app.security import get_current_user, require_internal_service_producer
from app.services import fact_service, finding_service, score_engine_service

router = APIRouter(prefix="/api/v1/investigations/{investigation_id}", tags=["facts-and-findings"])


@router.post("/facts", response_model=FactOut, status_code=201)
def create_fact(
    investigation_id: str,
    body: FactCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return fact_service.persist_fact(db, user=user, investigation_id=investigation_id, payload=body)


@router.get("/facts", response_model=list[FactOut])
def list_facts(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return fact_service.list_facts(db, user=user, investigation_id=investigation_id)


@router.post(
    "/findings", response_model=FindingOut, status_code=201,
    dependencies=[Depends(require_internal_service_producer)],
)
def create_finding(
    investigation_id: str,
    body: FindingCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Accepts a Finding submitted DIRECTLY by a trusted deterministic
    producer (e.g. hopzero-forensics). Requires BOTH a valid user JWT
    (for organization scoping / audit actor attribution) AND the
    X-Internal-Service-Key header (the actual credential proving the
    caller is an authorized deterministic producer -- see
    app/security.py::require_internal_service_producer). AI-derived
    findings must go through
    POST .../analysis-runs/{run_id}/ai-candidates
    instead, where strength is computed deterministically rather than
    trusted from the payload.
    """
    return finding_service.persist_finding(db, user=user, investigation_id=investigation_id, payload=body)


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    investigation_id: str,
    analysis_run_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return finding_service.list_findings(
        db, user=user, investigation_id=investigation_id, analysis_run_id=analysis_run_id
    )


@router.post("/analysis-runs/{run_id}/score", response_model=ScoreOut, status_code=201)
def compute_score(
    investigation_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Triggers the backend's own deterministic Score Engine followed by
    the Conclusion Generator against this investigation's currently
    validated Findings. There is no request body accepting
    total_score/severity/floors -- the backend derives every value
    itself. Immutable: a second call for the same run returns 409; a
    retry must use a new AnalysisRun.
    """
    score_row = score_engine_service.compute_and_persist_score(
        db, user=user, investigation_id=investigation_id, run_id=run_id
    )
    # Orchestration: invoke Conclusion Generator separately
    score_row = score_engine_service.generate_and_persist_conclusion(
        db, user=user, score_conclusion=score_row,
    )
    return score_row


@router.get("/analysis-runs/{run_id}/score", response_model=ScoreOut)
def get_score(
    investigation_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return score_engine_service.get_score(db, user=user, investigation_id=investigation_id, run_id=run_id)
