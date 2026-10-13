import logging
import threading
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, File, Query, status
from sqlalchemy.orm import Session

from app.database import get_db, SessionLocal
from app.models import User
from app.schemas import (
    InvestigationCreate,
    InvestigationOut,
    InvestigationStatusUpdate,
    AnalystActionCreate,
    AnalystActionOut,
    ArtifactOut,
    AuditEventOut,
    AnalysisResponse,
)
from app.security import get_current_user
from app.services import investigation_service, evidence_service, analysis_run_service
from app.services.pipeline_service import execute_analysis_pipeline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/investigations", tags=["investigations"])

MAX_ARTIFACT_BYTES = 25 * 1024 * 1024  # 25MB ceiling
_PIPELINE_SEMAPHORE = threading.Semaphore(4)  # Limit concurrent SQLite write pipelines


def _run_pipeline_worker(investigation_id: str, artifact_id: str, run_id: str, user_id: str):
    with _PIPELINE_SEMAPHORE:
        worker_db = SessionLocal()
        try:
            worker_user = worker_db.get(User, user_id)
            if not worker_user:
                logger.error(f"User {user_id} not found in background pipeline worker")
                return
            execute_analysis_pipeline(
                worker_db,
                user=worker_user,
                investigation_id=investigation_id,
                artifact_id=artifact_id,
                run_id=run_id,
            )
        except Exception as exc:
            logger.error(f"Background analysis pipeline error for run {run_id}: {exc}", exc_info=True)
        finally:
            worker_db.close()



@router.post("", response_model=InvestigationOut, status_code=201)
def create_investigation(
    body: InvestigationCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return investigation_service.create_investigation(db, user=user, title=body.title)


@router.get("", response_model=list[InvestigationOut])
def list_investigations(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return investigation_service.list_investigations(db, user=user)


@router.get("/{investigation_id}", response_model=InvestigationOut)
def get_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return investigation_service.get_investigation(db, user=user, investigation_id=investigation_id)






@router.post("/{investigation_id}/status", response_model=InvestigationOut, deprecated=True)
def update_status(
    investigation_id: str,
    body: InvestigationStatusUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """DEPRECATED: Direct status mutation. Use POST /{id}/actions with canonical analyst actions instead."""
    return investigation_service.transition_status(
        db, user=user, investigation_id=investigation_id, new_status=body.status
    )


@router.post("/{investigation_id}/actions", response_model=AnalystActionOut)
def perform_action(
    investigation_id: str,
    body: AnalystActionCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return investigation_service.record_analyst_action(
        db,
        user=user,
        investigation_id=investigation_id,
        action=body.action,
        note=body.note,
        false_positive_reason=body.falsePositiveReason,
    )


@router.post("/{investigation_id}/reopen", response_model=InvestigationOut, deprecated=True)
def reopen(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """DEPRECATED: Use POST /{id}/actions with action='reopen' instead."""
    return investigation_service.reopen_investigation(db, user=user, investigation_id=investigation_id)


@router.post("/{investigation_id}/artifacts", response_model=ArtifactOut, status_code=201)
async def upload_artifact(
    investigation_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    chunks = bytearray()
    while chunk := await file.read(1024 * 1024):
        chunks.extend(chunk)
        if len(chunks) > MAX_ARTIFACT_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Artifact exceeds maximum allowable size (25MB)",
            )
    content = bytes(chunks)

    return evidence_service.ingest_artifact(
        db,
        user=user,
        investigation_id=investigation_id,
        filename=file.filename or "artifact.eml",
        mime_type=file.content_type or "application/octet-stream",
        content=content,
    )


@router.get("/{investigation_id}/artifacts", response_model=list[ArtifactOut])
def list_artifacts(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return evidence_service.list_artifacts(db, user=user, investigation_id=investigation_id)


@router.post("/{investigation_id}/analyze", response_model=AnalysisResponse, status_code=202)
def start_analysis(
    investigation_id: str,
    background_tasks: BackgroundTasks,
    artifact_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    inv = investigation_service.get_investigation(db, user=user, investigation_id=investigation_id)

    if not artifact_id:
        artifacts = evidence_service.list_artifacts(db, user=user, investigation_id=str(inv.id))
        if not artifacts:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No artifacts found for this investigation to analyze",
            )
        target_artifact = artifacts[-1]
    else:
        target_artifact = evidence_service.get_artifact(db, user=user, investigation_id=str(inv.id), artifact_id=artifact_id)

    run = analysis_run_service.create_analysis_run(db, user=user, investigation_id=str(inv.id), artifact_id=str(target_artifact.id))
    db.commit()

    background_tasks.add_task(
        _run_pipeline_worker,
        str(inv.id),
        str(target_artifact.id),
        str(run.id),
        str(user.id),
    )

    return AnalysisResponse(
        investigation_id=str(inv.id),
        analysis_run_id=str(run.id),
        status="QUEUED",
    )


@router.get("/{investigation_id}/audit", response_model=list[AuditEventOut])
def get_audit_trail(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return investigation_service.get_investigation_audit_events(
        db, user=user, investigation_id=investigation_id
    )
