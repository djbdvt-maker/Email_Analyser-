import hashlib
import os
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.config import get_settings
from app.models import Artifact, AuditAction, User
from app.services.investigation_service import get_investigation

settings = get_settings()


def _storage_root() -> str:
    root = settings.artifact_storage_root
    os.makedirs(root, exist_ok=True)
    return root


def ingest_artifact(
    db: Session, *, user: User, investigation_id: str,
    filename: str, mime_type: str, content: bytes,
    ingestion_source: str | None = None,
    provider_message_id: str | None = None,
) -> Artifact:
    """
    Persists the original bytes unchanged and records SHA-256 (required)
    and MD5 (optional, best-effort) hashes computed over those exact
    bytes -- never over a re-derived or reformatted copy.
    """
    inv = get_investigation(db, user=user, investigation_id=investigation_id)

    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()

    stored_name = f"{uuid.uuid4()}_{filename}"
    path = os.path.join(_storage_root(), stored_name)
    with open(path, "wb") as f:
        f.write(content)

    artifact = Artifact(
        investigation_id=inv.id,
        storage_path=path,
        original_filename=filename,
        mime_type=mime_type,
        size_bytes=len(content),
        original_artifact_sha256=sha256,
        original_artifact_md5=md5,
        ingestion_source=ingestion_source,
        provider_message_id=provider_message_id,
    )
    db.add(artifact)
    db.flush()
    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.ARTIFACT_INGESTED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={"artifact_id": artifact.id, "sha256": sha256},
    )
    db.commit()
    db.refresh(artifact)
    return artifact


def get_artifact(db: Session, *, user: User, investigation_id: str, artifact_id: str) -> Artifact:
    """
    Read-only retrieval. Deliberately does NOT record EVIDENCE_EXPORTED
    or any other audit event -- viewing evidence metadata/bytes is not
    the same operation as exporting it.
    """
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    artifact = db.get(Artifact, artifact_id)
    if artifact is None or artifact.investigation_id != inv.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return artifact


def list_artifacts(db: Session, *, user: User, investigation_id: str) -> list[Artifact]:
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    return db.query(Artifact).filter(Artifact.investigation_id == inv.id).all()


def export_artifact(db: Session, *, user: User, investigation_id: str, artifact_id: str) -> Artifact:
    """
    The explicit, distinct export operation. This is the ONLY code path
    in the backend that computes export_bundle_sha256 and records
    EVIDENCE_EXPORTED. Nothing fabricates this hash speculatively --
    if the underlying file is unreadable, the operation fails rather
    than inventing a value.
    """
    artifact = get_artifact(db, user=user, investigation_id=investigation_id, artifact_id=artifact_id)

    if not os.path.exists(artifact.storage_path):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Underlying artifact bytes are missing; cannot export.",
        )

    with open(artifact.storage_path, "rb") as f:
        content = f.read()

    import io
    import json
    import zipfile

    exported_at_dt = datetime.now(timezone.utc)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(artifact.original_filename, content)
        manifest = {
            "artifact_id": artifact.id,
            "investigation_id": investigation_id,
            "original_filename": artifact.original_filename,
            "original_artifact_sha256": artifact.original_artifact_sha256,
            "size_bytes": artifact.size_bytes,
            "exported_at": exported_at_dt.isoformat(),
        }
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    bundle_bytes = buf.getvalue()
    export_hash = hashlib.sha256(bundle_bytes).hexdigest()

    artifact.export_bundle_sha256 = export_hash
    artifact.exported_at = exported_at_dt
    db.flush()

    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.EVIDENCE_EXPORTED,
        investigation_id=investigation_id,
        actor_user_id=user.id,
        metadata={"artifact_id": artifact.id, "export_bundle_sha256": export_hash},
    )
    db.commit()
    db.refresh(artifact)
    return artifact


def get_artifact_by_source_and_provider_id(
    db: Session, *, ingestion_source: str, provider_message_id: str
) -> Artifact | None:
    return (
        db.query(Artifact)
        .filter(
            Artifact.ingestion_source == ingestion_source,
            Artifact.provider_message_id == provider_message_id,
        )
        .first()
    )

