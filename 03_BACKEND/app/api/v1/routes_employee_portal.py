"""
Restricted Employee Security Portal API Router.
Provides zero-password authentication via 8-character Secret Codes.
Exposes strictly Level 1 & Level 2 progressive disclosure (Consumer Verdict & Actions).
Provides zero access to administrative controls, developer logs, or other employees' data.
"""
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, Form, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    EmployeeEnrollmentCode,
    Investigation,
    InvestigationStatus,
    ScoreConclusion,
    Fact,
    Organization,
    User,
    UserRole,
)
from app.schemas import (
    EmployeeCodeVerify,
    EmployeeTokenResponse,
    EmployeeScanResponse,
    EmployeeReportRequest,
)
from app.security import create_employee_token, get_current_employee
from app.services import evidence_service
from app.services.analysis_run_service import create_analysis_run
from app.services.pipeline_service import execute_analysis_pipeline
from app.api.v1.websockets import broadcast_event

router = APIRouter(
    prefix="/api/v1/portal",
    tags=["employee-portal"],
)


from app.api.v1.routes_auth import check_auth_rate_limit

MAX_SCAN_BYTES = 25 * 1024 * 1024  # 25MB RFC822 limit


@router.post(
    "/verify-code",
    response_model=EmployeeTokenResponse,
    summary="Authenticate employee with Secret Code",
    description="Validates the 8-character code sent by the SOC Administrator. Zero password setup required.",
)
def verify_secret_code(
    payload: EmployeeCodeVerify,
    request: Request,
    db: Session = Depends(get_db),
):
    check_auth_rate_limit(request, key_prefix="portal_code", max_attempts=15, window_seconds=60.0)
    code_normalized = payload.code.strip().upper()
    enrollment = (
        db.query(EmployeeEnrollmentCode)
        .filter(EmployeeEnrollmentCode.code == code_normalized)
        .first()
    )
    if not enrollment:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid secret code. Please verify the code provided by your administrator.",
        )
    if not bool(getattr(enrollment, "is_active", False)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This access code has been deactivated by your security administrator.",
        )

    setattr(enrollment, "last_used_at", datetime.now(timezone.utc))
    db.commit()

    org = db.get(Organization, enrollment.organization_id)
    org_name = org.name if org else "HopZero Security"

    token = create_employee_token(
        code_id=str(enrollment.id),
        organization_id=str(enrollment.organization_id),
        employee_email=str(enrollment.employee_email),
        employee_name=str(enrollment.employee_name) if enrollment.employee_name is not None else None,
    )

    return EmployeeTokenResponse(
        access_token=token,
        token_type="bearer",
        employee_email=str(enrollment.employee_email),
        employee_name=str(enrollment.employee_name) if enrollment.employee_name is not None else None,
        department=str(enrollment.department) if enrollment.department is not None else None,
        organization_name=str(org_name),
        code=str(enrollment.code),
    )


@router.get(
    "/me",
    summary="Get current employee profile",
)
def get_portal_profile(
    employee: dict = Depends(get_current_employee),
    db: Session = Depends(get_db),
):
    enrollment: EmployeeEnrollmentCode = employee["enrollment"]
    org = db.get(Organization, enrollment.organization_id)
    return {
        "employee_email": enrollment.employee_email,
        "employee_name": enrollment.employee_name,
        "department": enrollment.department,
        "organization_name": org.name if org else "HopZero Security",
        "code": enrollment.code,
        "scan_count": enrollment.scan_count,
        "report_count": enrollment.report_count,
    }


@router.post(
    "/scan",
    response_model=EmployeeScanResponse,
    summary="Scan suspicious email for threats (Level 1 & 2 Consumer Verdict)",
    description="Analyzes an email and returns strictly human-readable verdict and recommended actions.",
)
async def scan_email_as_employee(
    file: Optional[UploadFile] = File(None),
    raw_content: Optional[str] = Form(None),
    email_subject: Optional[str] = Form(None),
    employee: dict = Depends(get_current_employee),
    db: Session = Depends(get_db),
):
    # Determine raw email bytes with bounded memory consumption
    if file and file.filename:
        chunks = bytearray()
        while chunk := await file.read(1024 * 1024):
            chunks.extend(chunk)
            if len(chunks) > MAX_SCAN_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="Email artifact exceeds maximum allowable size (25MB)",
                )
        content = bytes(chunks)
        filename = file.filename
    elif raw_content:
        content = raw_content.encode("utf-8")
        if len(content) > MAX_SCAN_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Pasted email content exceeds maximum allowable size (25MB)",
            )
        filename = "pasted_email.eml"
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide an .eml email file or paste the email contents.",
        )

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Provided email content is empty.")

    enrollment: EmployeeEnrollmentCode = employee["enrollment"]

    # Locate fallback admin/system user for audit ownership
    admin_user = (
        db.query(User)
        .filter(User.organization_id == enrollment.organization_id)
        .filter(User.role.in_([UserRole.ADMIN, UserRole.ANALYST]))
        .first()
    )
    admin_id = str(admin_user.id) if admin_user else str(enrollment.created_by_user_id)

    # 1. Create Investigation tagged with employee details
    display_title = email_subject or f"Employee Scan: {filename}"
    inv = Investigation(
        organization_id=str(enrollment.organization_id),
        title=display_title[:255],
        status=InvestigationStatus.UNDER_REVIEW,
        created_by_user_id=admin_id,
        reported_by_employee=enrollment.employee_email,
        employee_code_id=str(enrollment.id),
    )
    db.add(inv)
    db.flush()

    # 2. Ingest artifact
    artifact = evidence_service.ingest_artifact(
        db,
        user=admin_user or User(id=admin_id, organization_id=enrollment.organization_id),
        investigation_id=str(inv.id),
        filename=filename,
        mime_type="message/rfc822",
        content=content,
        ingestion_source="employee_portal",
    )

    # 3. Execute analysis pipeline synchronously
    run = create_analysis_run(
        db,
        user=admin_user or User(id=admin_id, organization_id=enrollment.organization_id),
        investigation_id=str(inv.id),
        artifact_id=str(artifact.id),
    )
    execute_analysis_pipeline(
        db,
        user=admin_user or User(id=admin_id, organization_id=enrollment.organization_id),
        investigation_id=str(inv.id),
        artifact_id=str(artifact.id),
        run_id=str(run.id),
    )
    db.refresh(inv)

    # 4. Fetch ScoreConclusion & Facts
    score_conc = db.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == run.id).first()
    facts = db.query(Fact).filter(Fact.analysis_run_id == run.id).all()

    # Extract subject & sender from facts
    subject_val = email_subject or filename
    sender_val = "Unknown"
    for f in facts:
        p = f.payload if isinstance(f.payload, dict) else {}
        k = str(p.get("key") or f.fact_type)
        if k == "sender_address":
            sender_val = p.get("value") or sender_val
        elif k in ("subject_normalized", "envelope_metadata"):
            subject_val = p.get("subject") or p.get("value") or subject_val

    # Update investigation title if subject was normalized
    if subject_val and subject_val != filename:
        setattr(inv, "title", f"[{enrollment.employee_email}] {subject_val}"[:255])

    curr_scans = getattr(enrollment, "scan_count", 0)
    setattr(enrollment, "scan_count", int(str(curr_scans or 0)) + 1)
    setattr(enrollment, "last_used_at", datetime.now(timezone.utc))
    db.commit()

    # Broadcast to SOC Admin dashboard (tenant scoped)
    try:
        await broadcast_event(
            "investigation_updated",
            {
                "investigation_id": str(inv.id),
                "reported_by": str(enrollment.employee_email),
                "title": str(inv.title),
            },
            organization_id=str(enrollment.organization_id),
        )
    except Exception:
        pass

    # Determine consumer verdict
    score = int(str(score_conc.total_score)) if score_conc and score_conc.total_score is not None else 0
    sev = str(score_conc.severity) if score_conc and score_conc.severity is not None else "LOW"
    verdict = str(score_conc.verdict or "SAFE") if score_conc else "SAFE"
    if score >= 40 or sev in ("HIGH", "CRITICAL"):
        verdict = "DANGEROUS"
        recommendation = "🚨 High Risk Threat: Do NOT click links, open attachments, or reply. Report this email immediately."
        has_threats = True
    elif score >= 15 or sev == "MEDIUM":
        verdict = "SUSPICIOUS"
        recommendation = "⚠️ Suspicious Signals Detected: Treat with caution. Confirm sender identity before proceeding."
        has_threats = True
    else:
        verdict = "SAFE"
        recommendation = "✅ No elevated forensic threats detected. Always remain vigilant with unsolicited requests."
        has_threats = False

    explanation_val = getattr(score_conc, "one_line_explanation", None) if score_conc else None
    explanation = str(explanation_val) if explanation_val else "Forensic inspection complete."
    why_val = getattr(score_conc, "why_explanation", None) if score_conc else None
    why_text = str(why_val) if why_val else explanation

    return EmployeeScanResponse(
        investigation_id=str(inv.id),
        analysis_run_id=str(run.id),
        verdict=verdict,
        severity=sev,
        score=score,
        confidence="HIGH" if score > 0 else "MEDIUM",
        one_line_explanation=explanation,
        why_explanation=why_text,
        action_recommendation=recommendation,
        subject=subject_val,
        sender=sender_val,
        has_threats=has_threats,
        is_reported=False,
    )


@router.post(
    "/report",
    summary="Report/escalate email to SOC Security Administrator",
    description="Alerts the SOC team that an employee has flagged an email as a potential attack.",
)
async def report_threat_to_soc(
    payload: EmployeeReportRequest,
    employee: dict = Depends(get_current_employee),
    db: Session = Depends(get_db),
):
    inv = db.get(Investigation, payload.investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation record not found")

    enrollment: EmployeeEnrollmentCode = employee["enrollment"]

    setattr(inv, "status", InvestigationStatus.UNDER_REVIEW)
    setattr(inv, "reported_by_employee", str(enrollment.employee_email))
    if payload.employee_notes:
        setattr(inv, "employee_notes", payload.employee_notes)

    curr_reports = getattr(enrollment, "report_count", 0)
    setattr(enrollment, "report_count", int(str(curr_reports or 0)) + 1)
    setattr(enrollment, "last_used_at", datetime.now(timezone.utc))
    db.commit()

    # Broadcast high-priority alert to SOC Admin (tenant scoped)
    try:
        await broadcast_event(
            "investigation_updated",
            {
                "investigation_id": str(inv.id),
                "reported_by": str(enrollment.employee_email),
                "action": "reported_by_employee",
                "title": str(inv.title),
            },
            organization_id=str(enrollment.organization_id),
        )
    except Exception:
        pass

    return {
        "status": "reported",
        "investigation_id": str(inv.id),
        "message": "Incident successfully reported! Your SOC security team has been alerted.",
    }
