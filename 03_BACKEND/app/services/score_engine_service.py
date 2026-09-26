from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.models import ScoreConclusion, User, AnalysisRunStatus, AuditAction
from app.services.analysis_run_service import get_analysis_run
from app.services.finding_service import list_findings
from app.services.investigation_service import get_investigation
from app.services.score_engine import compute_score, SCORE_ENGINE_VERSION


def compute_and_persist_score(
    db: Session, *, user: User, investigation_id: str, run_id: str,
    provenance_extra: dict | None = None,
) -> ScoreConclusion:
    """
    Triggers the backend's own deterministic Score Engine ONLY.
    Produces ScoreOutput (numeric score, category caps, floors, severity)
    and persists it. Does NOT instantiate or invoke the Conclusion Generator —
    that is the orchestration layer's responsibility (pipeline_service).

    There is no parameter here for a caller-supplied
    total_score/severity/floors/verdict -- the only inputs are investigation_id/run_id,
    used solely to select which validated Findings to score and which run to attach the
    result to.
    """
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    run = get_analysis_run(db, user=user, run_id=run_id, investigation_id=inv.id)

    if run.status not in (AnalysisRunStatus.SCORING, AnalysisRunStatus.COMPLETED):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Score can only be computed for a run in SCORING or COMPLETED state",
        )

    existing = db.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == run.id).one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A Score already exists for this analysis run and is immutable. "
                    "A retry must use a new AnalysisRun.",
        )

    # Cross-run finding isolation: score only findings belonging to this exact run.
    from app.models import Finding
    findings = db.query(Finding).filter(
        Finding.investigation_id == inv.id,
        Finding.analysis_run_id == run.id,
    ).all()

    # Score Engine computes numeric score, caps, floors, severity
    result = compute_score(findings)

    prov = {
        "score_engine_version": SCORE_ENGINE_VERSION,
        "input_finding_ids": result.finding_ids_used,
    }
    if provenance_extra:
        prov.update(provenance_extra)

    row = ScoreConclusion(
        investigation_id=inv.id,
        analysis_run_id=run.id,
        total_score=result.total_score,
        severity=result.severity,
        verdict=None,  # Populated by Conclusion Generator in orchestration layer
        one_line_explanation=None,  # Populated by Conclusion Generator
        why_explanation=None,  # Populated by Conclusion Generator
        category_breakdown=result.category_breakdown,
        triggered_floor_codes=result.triggered_floor_codes,
        conclusion_text="",  # Populated by Conclusion Generator
        provenance=prov,
    )
    db.add(row)
    db.flush()
    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.SCORE_CONCLUSION_PERSISTED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={
            "analysis_run_id": run.id,
            "severity": result.severity,
            "total_score": result.total_score,
            "triggered_floor_codes": result.triggered_floor_codes,
        },
    )
    db.commit()
    db.refresh(row)
    return row


def generate_and_persist_conclusion(
    db: Session, *, user: User, score_conclusion: ScoreConclusion,
    findings: list | None = None, ai_status: str | None = None,
) -> ScoreConclusion:
    """
    Invokes the authoritative deterministic Conclusion Generator to populate
    verdict, one_line_explanation, why_explanation, and conclusion_text on
    an existing ScoreConclusion row.

    The Score Engine is NOT involved here — this is strictly conclusion
    generation using the already-computed ScoreOutput values.

    Must be called by the orchestration layer (pipeline_service) AFTER
    compute_and_persist_score() has completed.
    """
    from app.services.conclusion_generator import ConclusionGenerator
    from app.services.score_engine import ScoreResult

    # Reconstruct ScoreOutput from persisted ScoreConclusion
    score_output = ScoreResult(
        total_score=score_conclusion.total_score,
        severity=score_conclusion.severity,
        category_breakdown=score_conclusion.category_breakdown,
        triggered_floor_codes=score_conclusion.triggered_floor_codes,
        finding_ids_used=[],  # Already persisted in provenance
    )

    cg = ConclusionGenerator()
    conclusion_output = cg.generate(
        score_output=score_output,
        findings=findings,
        ai_status=ai_status,
    )

    conclusion_text = f"{conclusion_output.one_line_explanation} {conclusion_output.why_explanation}".strip()

    score_conclusion.verdict = conclusion_output.verdict
    score_conclusion.one_line_explanation = conclusion_output.one_line_explanation
    score_conclusion.why_explanation = conclusion_output.why_explanation
    score_conclusion.conclusion_text = conclusion_text

    current_prov = dict(score_conclusion.provenance or {})
    if conclusion_output.provenance:
        current_prov.update(conclusion_output.provenance)
    score_conclusion.provenance = current_prov

    db.flush()
    db.commit()
    db.refresh(score_conclusion)
    return score_conclusion


def get_score(db: Session, *, user: User, investigation_id: str, run_id: str) -> ScoreConclusion:
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    run = get_analysis_run(db, user=user, run_id=run_id, investigation_id=inv.id)
    row = db.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == run.id).one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No score computed for this run yet")
    return row
