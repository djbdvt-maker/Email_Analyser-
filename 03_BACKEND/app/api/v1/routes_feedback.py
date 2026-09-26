"""
API Router for User Feedback & Comparative Re-Analysis.
======================================================
Provides endpoints for:
- POST /api/v1/investigations/{id}/feedback
- GET /api/v1/investigations/{id}/feedback
- GET /api/v1/investigations/{id}/compare-runs
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import UserFeedbackCreate, UserFeedbackOut, RunComparisonOut
from app.security import get_current_user
from app.services import reanalysis_service

router = APIRouter(prefix="/api/v1/investigations/{investigation_id}", tags=["feedback-and-reanalysis"])


@router.post("/feedback", response_model=dict, status_code=201)
def submit_feedback(
    investigation_id: str,
    body: UserFeedbackCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Submits user feedback (SPAM_REPORTED, PHISHING_REPORTED, ANALYSIS_DISPUTED)
    and starts a new forensic re-analysis run without directly mutating scores or verdicts.
    """
    return reanalysis_service.submit_user_feedback_and_reanalyze(
        db,
        user=user,
        investigation_id=investigation_id,
        feedback_type=body.feedback_type,
        note=body.note,
        source_analysis_run_id=body.source_analysis_run_id,
    )


@router.get("/feedback", response_model=List[UserFeedbackOut])
def list_feedback(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Lists all user feedback entries recorded for this investigation."""
    return reanalysis_service.list_user_feedbacks(
        db, user=user, investigation_id=investigation_id
    )


@router.get("/compare-runs", response_model=RunComparisonOut)
def compare_runs(
    investigation_id: str,
    run1: str = Query(..., description="Base analysis run ID"),
    run2: str = Query(..., description="Target analysis run ID to compare against base"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Compares two analysis runs for an investigation, returning score deltas,
    severity changes, verdict changes, and findings discovered/resolved.
    """
    return reanalysis_service.compare_analysis_runs(
        db,
        user=user,
        investigation_id=investigation_id,
        run_1_id=run1,
        run_2_id=run2,
    )
