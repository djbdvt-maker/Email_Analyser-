from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import ArtifactOut, EvidenceExportOut
from app.security import get_current_user
from app.services import evidence_service

router = APIRouter(prefix="/api/v1/investigations/{investigation_id}/evidence", tags=["evidence"])

MAX_ARTIFACT_BYTES = 25 * 1024 * 1024  # 25MB ceiling


@router.post("", response_model=ArtifactOut, status_code=201)
async def ingest_evidence(
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
                detail="ARTIFACT_TOO_LARGE: Artifact exceeds 25MB ceiling.",
            )
    content = bytes(chunks)
    return evidence_service.ingest_artifact(
        db, user=user, investigation_id=investigation_id,
        filename=file.filename or "evidence.eml", mime_type=file.content_type or "application/octet-stream",
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

    artifact = evidence_service.export_artifact(
        db, user=user, investigation_id=investigation_id, artifact_id=artifact_id
    )
    return EvidenceExportOut(
        artifact_id=str(artifact.id),
        export_bundle_sha256=str(artifact.export_bundle_sha256),
        exported_at=getattr(artifact, "exported_at"),
    )
