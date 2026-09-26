from fastapi import APIRouter, Depends, UploadFile, File
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import ArtifactOut, EvidenceExportOut
from app.security import get_current_user
from app.services import evidence_service

router = APIRouter(prefix="/api/v1/investigations/{investigation_id}/evidence", tags=["evidence"])


@router.post("", response_model=ArtifactOut, status_code=201)
async def ingest_evidence(
    investigation_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    content = await file.read()
    return evidence_service.ingest_artifact(
        db, user=user, investigation_id=investigation_id,
        filename=file.filename, mime_type=file.content_type or "application/octet-stream",
        content=content,
    )


@router.get("", response_model=list[ArtifactOut])
def list_evidence(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Read-only retrieval. Does NOT generate an EVIDENCE_EXPORTED audit
    event -- see the explicit export endpoint below.
    """
    return evidence_service.list_artifacts(db, user=user, investigation_id=investigation_id)


@router.get("/{artifact_id}", response_model=ArtifactOut)
def get_evidence(
    investigation_id: str,
    artifact_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Read-only retrieval of a single artifact's metadata."""
    return evidence_service.get_artifact(
        db, user=user, investigation_id=investigation_id, artifact_id=artifact_id
    )


@router.post("/{artifact_id}/export", response_model=EvidenceExportOut)
def export_evidence(
    investigation_id: str,
    artifact_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    The only endpoint that produces an EVIDENCE_EXPORTED audit event
    and computes export_bundle_sha256.
    """
    artifact = evidence_service.export_artifact(
        db, user=user, investigation_id=investigation_id, artifact_id=artifact_id
    )
    return EvidenceExportOut(
        artifact_id=artifact.id,
        export_bundle_sha256=artifact.export_bundle_sha256,
        exported_at=artifact.exported_at,
    )
