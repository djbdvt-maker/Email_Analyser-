from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.models import AnalysisRun, AnalysisRunStatus, AuditAction, User
from app.services.investigation_service import get_investigation

_ALLOWED_TRANSITIONS: dict[AnalysisRunStatus, set[AnalysisRunStatus]] = {
    AnalysisRunStatus.QUEUED: {AnalysisRunStatus.PARSING, AnalysisRunStatus.CANCELLED},
    AnalysisRunStatus.PARSING: {AnalysisRunStatus.ANALYZING, AnalysisRunStatus.FAILED, AnalysisRunStatus.CANCELLED},
    AnalysisRunStatus.ANALYZING: {AnalysisRunStatus.SCORING, AnalysisRunStatus.FAILED, AnalysisRunStatus.CANCELLED},
    AnalysisRunStatus.SCORING: {AnalysisRunStatus.COMPLETED, AnalysisRunStatus.FAILED, AnalysisRunStatus.CANCELLED},
    AnalysisRunStatus.COMPLETED: set(),
    AnalysisRunStatus.FAILED: set(),
    AnalysisRunStatus.CANCELLED: set(),
}

_TERMINAL_USABLE = {AnalysisRunStatus.COMPLETED}


def create_analysis_run(db: Session, *, user: User, investigation_id: str, artifact_id: str) -> AnalysisRun:
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    run = AnalysisRun(investigation_id=inv.id, artifact_id=artifact_id, status=AnalysisRunStatus.QUEUED)
    db.add(run)
    db.flush()
    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.ANALYSIS_RUN_CREATED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={"analysis_run_id": run.id},
    )
    db.commit()
    db.refresh(run)
    return run


def get_analysis_run(
    db: Session, *, user: User, run_id: str, investigation_id: str | None = None
) -> AnalysisRun:
    run = db.get(AnalysisRun, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    # org-scope via parent investigation
    get_investigation(db, user=user, investigation_id=run.investigation_id)
    # If the caller reached this run through a specific investigation's
    # path (e.g. /investigations/{investigation_id}/analysis-runs/{run_id}),
    # make sure the run actually belongs to that investigation rather than
    # silently succeeding against a mismatched but org-owned investigation.
    if investigation_id is not None and run.investigation_id != investigation_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return run


def list_analysis_runs(db: Session, *, user: User, investigation_id: str) -> list[AnalysisRun]:
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    return (
        db.query(AnalysisRun)
        .filter(AnalysisRun.investigation_id == inv.id)
        .order_by(AnalysisRun.created_at.desc())
        .all()
    )


def transition_run_status(
    db: Session, *, user: User, run_id: str, new_status: AnalysisRunStatus,
    failure_reason: str | None = None, investigation_id: str | None = None,
) -> AnalysisRun:
    run = get_analysis_run(db, user=user, run_id=run_id, investigation_id=investigation_id)

    allowed = _ALLOWED_TRANSITIONS.get(run.status, set())
    if new_status not in allowed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot transition analysis run from {run.status.value} to {new_status.value}",
        )

    old_status = run.status
    run.status = new_status

    if new_status == AnalysisRunStatus.PARSING and run.started_at is None:
        run.started_at = datetime.now(timezone.utc)

    if new_status == AnalysisRunStatus.FAILED and failure_reason:
        run.failure_reason = failure_reason

    if new_status in (AnalysisRunStatus.COMPLETED, AnalysisRunStatus.FAILED, AnalysisRunStatus.CANCELLED):
        run.completed_at = datetime.now(timezone.utc)

    db.flush()

    inv = get_investigation(db, user=user, investigation_id=run.investigation_id)

    # ---- current_analysis_run_id semantics (locked for MVP) ----
    # Only a COMPLETED run may ever become the current run. Failed or
    # cancelled runs never replace it, and there is no manual
    # set_current_run action -- this is the only place this field is
    # ever written.
    if new_status in _TERMINAL_USABLE:
        inv.current_analysis_run_id = run.id

    db.flush()
    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.ANALYSIS_RUN_STATUS_CHANGED,
        investigation_id=run.investigation_id,
        actor_user_id=user.id,
        metadata={
            "analysis_run_id": run.id,
            "from": old_status.value,
            "to": new_status.value,
            "became_current_run": new_status in _TERMINAL_USABLE,
        },
    )
    db.commit()
    db.refresh(run)
    return run
