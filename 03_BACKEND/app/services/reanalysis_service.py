"""
User-Guided Re-Analysis & Run Comparison Service.
================================================
Implements:
1. User Feedback Submission (SPAM_REPORTED, PHISHING_REPORTED, ANALYSIS_DISPUTED).
2. Safe Re-Analysis Workflow:
   - Records feedback event without directly altering score/verdict.
   - Spawns a NEW AnalysisRun.
   - Preserves previous AnalysisRun as immutable historical baseline.
   - Executes full forensic re-analysis pipeline on the same immutable artifact.
   - Computes new findings, new score, floor evaluation, and new conclusion.
   - Updates current_analysis_run_id ONLY if new run successfully completes.
3. Comparative Analysis between runs (score delta, severity delta, verdict delta, new findings).
"""
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.models import (
    Investigation,
    AnalysisRun,
    AnalysisRunStatus,
    Artifact,
    Finding,
    ScoreConclusion,
    UserFeedback,
    FeedbackType,
    User,
    AuditAction,
)
from app.services.investigation_service import get_investigation
from app.services.analysis_run_service import create_analysis_run, get_analysis_run
from app.services.pipeline_service import execute_analysis_pipeline

logger = logging.getLogger(__name__)

ALLOWED_FEEDBACK_TYPES = {
    FeedbackType.SPAM_REPORTED.value,
    FeedbackType.PHISHING_REPORTED.value,
    FeedbackType.ANALYSIS_DISPUTED.value,
}


def submit_user_feedback_and_reanalyze(
    db: Session,
    *,
    user: User,
    investigation_id: str,
    feedback_type: str,
    note: Optional[str] = None,
    source_analysis_run_id: Optional[str] = None,
    ai_simulated_failure: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Records user feedback, audits the event, and triggers a full forensic re-analysis run.
    The feedback does NOT directly overwrite score, severity, or verdict.
    The previous AnalysisRun remains completely immutable.
    """
    inv = get_investigation(db, user=user, investigation_id=investigation_id)

    # 1. Validate feedback type
    norm_feedback_type = (feedback_type or "").upper().strip()
    if norm_feedback_type not in ALLOWED_FEEDBACK_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid feedback_type '{feedback_type}'. Must be one of {sorted(list(ALLOWED_FEEDBACK_TYPES))}",
        )

    # 2. Determine source run
    src_run_id = source_analysis_run_id or inv.current_analysis_run_id
    if not src_run_id:
        # Check any run
        last_run = (
            db.query(AnalysisRun)
            .filter(AnalysisRun.investigation_id == inv.id)
            .order_by(AnalysisRun.created_at.desc())
            .first()
        )
        if last_run:
            src_run_id = last_run.id
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot submit feedback for investigation with no analysis runs.",
            )

    src_run = db.get(AnalysisRun, src_run_id)
    if not src_run or src_run.investigation_id != inv.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source analysis run {src_run_id} not found in this investigation.",
        )

    # 3. Create persisted feedback entity
    feedback = UserFeedback(
        organization_id=user.organization_id,
        investigation_id=inv.id,
        source_analysis_run_id=src_run.id,
        actor_user_id=user.id,
        feedback_type=norm_feedback_type,
        note=note,
    )
    db.add(feedback)
    db.flush()

    # 4. Record audit event for feedback submission
    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.USER_FEEDBACK_SUBMITTED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={
            "feedback_id": feedback.id,
            "feedback_type": norm_feedback_type,
            "source_analysis_run_id": src_run.id,
            "note": note,
        },
    )
    db.commit()

    # 5. Find the primary artifact for the investigation
    artifact = (
        db.query(Artifact)
        .filter(Artifact.investigation_id == inv.id)
        .order_by(Artifact.ingested_at.asc())
        .first()
    )
    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No artifact found for investigation {inv.id} to re-analyze.",
        )

    # 6. Create NEW AnalysisRun (immutable previous run preserved)
    new_run = create_analysis_run(db, user=user, investigation_id=inv.id, artifact_id=src_run.artifact_id)
    feedback.resulting_analysis_run_id = new_run.id
    db.commit()

    # 7. Record audit event for re-analysis request
    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.REANALYSIS_REQUESTED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={
            "feedback_id": feedback.id,
            "source_run_id": src_run.id,
            "new_analysis_run_id": new_run.id,
        },
    )
    db.commit()

    # 8. Execute pipeline synchronously for the new run
    pipeline_result = execute_analysis_pipeline(
        db,
        user=user,
        investigation_id=inv.id,
        artifact_id=artifact.id,
        run_id=new_run.id,
        ai_simulated_failure=ai_simulated_failure,
    )

    db.refresh(inv)
    db.refresh(new_run)
    db.refresh(feedback)

    return {
        "feedback_id": feedback.id,
        "investigation_id": inv.id,
        "source_analysis_run_id": src_run.id,
        "new_analysis_run_id": new_run.id,
        "feedback_type": feedback.feedback_type,
        "new_run_status": new_run.status.value,
        "new_score": pipeline_result.get("total_score"),
        "new_severity": pipeline_result.get("severity"),
        "current_analysis_run_id": inv.current_analysis_run_id,
    }


def list_user_feedbacks(
    db: Session,
    *,
    user: User,
    investigation_id: str,
) -> List[UserFeedback]:
    """Lists all user feedback records for an investigation."""
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    return (
        db.query(UserFeedback)
        .filter(UserFeedback.investigation_id == inv.id)
        .order_by(UserFeedback.created_at.desc())
        .all()
    )


def compare_analysis_runs(
    db: Session,
    *,
    user: User,
    investigation_id: str,
    run_1_id: str,
    run_2_id: str,
) -> Dict[str, Any]:
    """
    Compares two analysis runs of the same investigation, reporting score delta,
    severity changes, verdict changes, and findings discovered/resolved.
    """
    inv = get_investigation(db, user=user, investigation_id=investigation_id)

    run1 = get_analysis_run(db, user=user, run_id=run_1_id, investigation_id=inv.id)
    run2 = get_analysis_run(db, user=user, run_id=run_2_id, investigation_id=inv.id)

    score1 = db.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == run1.id).first()
    score2 = db.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == run2.id).first()

    findings1 = (
        db.query(Finding)
        .filter(Finding.investigation_id == inv.id, Finding.analysis_run_id == run1.id)
        .all()
    )
    findings2 = (
        db.query(Finding)
        .filter(Finding.investigation_id == inv.id, Finding.analysis_run_id == run2.id)
        .all()
    )

    def finding_key(f: Finding) -> str:
        return f"{f.category}|{f.qualification_code}|{f.claim_signature}|{f.normalized_subject_or_target}"

    f1_map = {finding_key(f): f for f in findings1}
    f2_map = {finding_key(f): f for f in findings2}

    new_findings = [
        {
            "id": f.id,
            "category": f.category,
            "qualification_code": f.qualification_code,
            "strength": f.strength,
            "claim_signature": f.claim_signature,
            "target": f.normalized_subject_or_target,
            "supporting_text": f.supporting_text,
        }
        for k, f in f2_map.items()
        if k not in f1_map
    ]

    resolved_findings = [
        {
            "id": f.id,
            "category": f.category,
            "qualification_code": f.qualification_code,
            "strength": f.strength,
            "claim_signature": f.claim_signature,
            "target": f.normalized_subject_or_target,
            "supporting_text": f.supporting_text,
        }
        for k, f in f1_map.items()
        if k not in f2_map
    ]

    unchanged_findings = [
        {
            "id": f.id,
            "category": f.category,
            "qualification_code": f.qualification_code,
            "strength": f.strength,
            "claim_signature": f.claim_signature,
            "target": f.normalized_subject_or_target,
        }
        for k, f in f2_map.items()
        if k in f1_map
    ]

    s1_score = score1.total_score if score1 else None
    s2_score = score2.total_score if score2 else None
    score_delta = (s2_score - s1_score) if (s1_score is not None and s2_score is not None) else None

    s1_sev = score1.severity if score1 else None
    s2_sev = score2.severity if score2 else None
    sev_changed = s1_sev != s2_sev

    s1_verdict = score1.verdict if score1 else None
    s2_verdict = score2.verdict if score2 else None
    verdict_changed = s1_verdict != s2_verdict

    summary_parts = []
    if score_delta is not None:
        sign = "+" if score_delta > 0 else ""
        summary_parts.append(f"Score changed by {sign}{score_delta} ({s1_score} -> {s2_score})")
    if sev_changed:
        summary_parts.append(f"Severity changed from {s1_sev} to {s2_sev}")
    if verdict_changed:
        summary_parts.append(f"Verdict changed from {s1_verdict} to {s2_verdict}")
    if new_findings:
        summary_parts.append(f"{len(new_findings)} new findings identified in run {run2.id[:8]}")

    summary = "; ".join(summary_parts) if summary_parts else "Analysis runs are identical in findings and scores."

    return {
        "investigation_id": inv.id,
        "run_1_id": run1.id,
        "run_2_id": run2.id,
        "run_1_score": s1_score,
        "run_2_score": s2_score,
        "score_delta": score_delta,
        "run_1_severity": s1_sev,
        "run_2_severity": s2_sev,
        "severity_changed": sev_changed,
        "run_1_verdict": s1_verdict,
        "run_2_verdict": s2_verdict,
        "verdict_changed": verdict_changed,
        "new_findings": new_findings,
        "unchanged_findings": unchanged_findings,
        "resolved_findings": resolved_findings,
        "summary": summary,
    }
