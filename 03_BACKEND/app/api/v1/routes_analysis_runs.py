from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import AnalysisRunOut, AnalysisRunStatusUpdate
from app.security import get_current_user
from app.services import analysis_run_service

router = APIRouter(prefix="/api/v1/investigations/{investigation_id}/analysis-runs", tags=["analysis-runs"])


# POST /analysis-runs removed as per strict architectural guidelines. 
# Runs are created via ingestion or feedback/reanalysis only.


@router.get("", response_model=list[AnalysisRunOut])
def list_analysis_runs(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return analysis_run_service.list_analysis_runs(db, user=user, investigation_id=investigation_id)


@router.get("/{run_id}", response_model=AnalysisRunOut)
def get_analysis_run(
    investigation_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return analysis_run_service.get_analysis_run(
        db, user=user, run_id=run_id, investigation_id=investigation_id
    )


@router.post("/{run_id}/status", response_model=AnalysisRunOut)
def update_run_status(
    investigation_id: str,
    run_id: str,
    body: AnalysisRunStatusUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return analysis_run_service.transition_run_status(
        db, user=user, run_id=run_id, new_status=body.status,
        failure_reason=body.failure_reason, investigation_id=investigation_id,
    )
