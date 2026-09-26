import io
import json
import zipfile
import hashlib
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, Investigation, Artifact, ScoreConclusion, AuditEvent
from app.security import get_current_user

router = APIRouter(prefix="/api/v1/investigations", tags=["investigations_export"])

@router.get("/{investigation_id}/export")
def export_chain_of_custody(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    inv = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.organization_id == user.organization_id
    ).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    artifact = db.query(Artifact).filter(Artifact.investigation_id == inv.id).order_by(Artifact.ingested_at.desc()).first()
    if not artifact:
        raise HTTPException(status_code=404, detail="No evidence artifact found")

    try:
        with open(artifact.storage_path, "rb") as f:
            eml_bytes = f.read()
    except Exception:
        raise HTTPException(status_code=500, detail="Original EML file missing from storage")

    score = db.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == inv.current_analysis_run_id).first()
    
    report_dict = {
        "investigation_id": inv.id,
        "title": inv.title,
        "status": inv.status.value,
        "created_at": inv.created_at.isoformat(),
        "score_data": {
            "total_score": score.total_score if score else None,
            "severity": score.severity if score else None,
            "verdict": score.verdict if score else None
        }
    }
    report_bytes = json.dumps(report_dict, indent=2).encode("utf-8")
    
    eml_hash = hashlib.sha256(eml_bytes).hexdigest()
    report_hash = hashlib.sha256(report_bytes).hexdigest()
    
    manifest_content = f"Chain of Custody Manifest\n\nArtifact: {artifact.original_filename}\nSHA-256: {eml_hash}\n\nReport: report.json\nSHA-256: {report_hash}\n"
    manifest_bytes = manifest_content.encode("utf-8")
    
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr(artifact.original_filename, eml_bytes)
        zip_file.writestr("report.json", report_bytes)
        zip_file.writestr("manifest.sha256", manifest_bytes)
    
    return StreamingResponse(
        iter([zip_buffer.getvalue()]), 
        media_type="application/zip", 
        headers={"Content-Disposition": f"attachment; filename=hopzero_forensic_export_{inv.id}.zip"}
    )
