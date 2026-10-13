"""
API Router for SOC Admin Employee Code Provisioning and Distribution.
Allows the SOC Admin to generate unique pairing codes, trigger invitation emails via SMTP,
and audit active employee access.
"""
import secrets
import string
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserRole, EmployeeEnrollmentCode, Organization
from app.schemas import EmployeeCodeCreate, EmployeeCodeOut
from app.security import get_current_user, require_role, assert_same_org
from app.services.email_sender_service import send_employee_invitation

router = APIRouter(
    prefix="/api/v1/admin/employees",
    tags=["admin-employees"],
)

# Secure character set excluding ambiguous characters (0, O, 1, I, L)
_CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"


def _generate_secret_code() -> str:
    """Generates an 8-character formatted code like HZ-8X42-M9K."""
    part1 = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(4))
    part2 = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(4))
    return f"HZ-{part1}-{part2}"


@router.post(
    "/generate",
    response_model=EmployeeCodeOut,
    status_code=status.HTTP_201_CREATED,
    summary="Generate employee access code and send invitation",
    description="Creates an employee secret pairing code and optionally dispatches an invitation email via SMTP.",
)
def generate_employee_code(
    payload: EmployeeCodeCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("ADMIN", "ANALYST")),
):
    # Ensure code uniqueness
    for _ in range(10):
        code_str = _generate_secret_code()
        existing = db.query(EmployeeEnrollmentCode).filter(EmployeeEnrollmentCode.code == code_str).first()
        if not existing:
            break
    else:
        raise HTTPException(status_code=500, detail="Could not generate unique code")

    enrollment = EmployeeEnrollmentCode(
        organization_id=user.organization_id,
        created_by_user_id=user.id,
        code=code_str,
        employee_email=payload.employee_email.strip().lower(),
        employee_name=payload.employee_name.strip() if payload.employee_name else None,
        department=payload.department.strip() if payload.department else None,
        is_active=True,
    )
    db.add(enrollment)
    db.flush()

    org = db.get(Organization, user.organization_id)
    org_name = org.name if org else "HopZero Security"

    invitation_status = "not_sent"
    if payload.send_email:
        emp_name_val = getattr(enrollment, "employee_name", None)
        email_result = send_employee_invitation(
            employee_email=str(enrollment.employee_email),
            employee_name=str(emp_name_val) if emp_name_val is not None else None,
            secret_code=str(enrollment.code),
            organization_name=str(org_name),
        )
        if email_result.get("delivered"):
            setattr(enrollment, "invitation_sent_at", datetime.now(timezone.utc))
            invitation_status = email_result.get("status", "sent")
        else:
            invitation_status = f"error: {email_result.get('error', 'failed')}"

    db.commit()
    db.refresh(enrollment)

    out = EmployeeCodeOut.model_validate(enrollment)
    out.invitation_status = invitation_status
    return out


@router.get(
    "",
    response_model=List[EmployeeCodeOut],
    summary="List employee enrollment codes",
    description="Lists all issued employee secret codes for the administrator's organization.",
)
def list_employee_codes(
    db: Session = Depends(get_db),
    user: User = Depends(require_role("ADMIN", "ANALYST")),
):
    codes = (
        db.query(EmployeeEnrollmentCode)
        .filter(EmployeeEnrollmentCode.organization_id == user.organization_id)
        .order_by(EmployeeEnrollmentCode.created_at.desc())
        .all()
    )
    return [EmployeeCodeOut.model_validate(c) for c in codes]


@router.post(
    "/{code_id}/resend",
    response_model=EmployeeCodeOut,
    summary="Resend invitation email to employee",
)
def resend_invitation(
    code_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("ADMIN", "ANALYST")),
):
    enrollment = db.get(EmployeeEnrollmentCode, code_id)
    if not enrollment:
        raise HTTPException(status_code=404, detail="Employee code not found")
    assert_same_org(user, str(enrollment.organization_id))

    org = db.get(Organization, user.organization_id)
    org_name = org.name if org else "HopZero Security"

    emp_name_val = getattr(enrollment, "employee_name", None)
    email_result = send_employee_invitation(
        employee_email=str(enrollment.employee_email),
        employee_name=str(emp_name_val) if emp_name_val is not None else None,
        secret_code=str(enrollment.code),
        organization_name=str(org_name),
    )
    if email_result.get("delivered"):
        setattr(enrollment, "invitation_sent_at", datetime.now(timezone.utc))
        invitation_status = email_result.get("status", "sent")
    else:
        invitation_status = f"error: {email_result.get('error', 'failed')}"

    db.commit()
    db.refresh(enrollment)

    out = EmployeeCodeOut.model_validate(enrollment)
    out.invitation_status = invitation_status
    return out


@router.delete(
    "/{code_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke employee access code",
)
def revoke_employee_code(
    code_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("ADMIN")),
):
    enrollment = db.get(EmployeeEnrollmentCode, code_id)
    if not enrollment:
        raise HTTPException(status_code=404, detail="Employee code not found")
    assert_same_org(user, str(enrollment.organization_id))

    setattr(enrollment, "is_active", False)
    db.commit()
    return None


@router.get(
    "/download-extension",
    summary="Download distributable employee browser extension package",
)
def download_extension(
    user: User = Depends(require_role("ADMIN", "ANALYST")),
):
    from fastapi.responses import FileResponse
    from pathlib import Path
    import sys

    repo_root = Path(__file__).resolve().parent.parent.parent.parent.parent
    dist_zip = repo_root / "dist" / "hopzero-employee-extension.zip"
    if not dist_zip.exists():
        sys.path.insert(0, str(repo_root))
        from scripts.package_extension import package_extension
        dist_zip = package_extension()

    return FileResponse(
        path=str(dist_zip),
        media_type="application/zip",
        filename="hopzero-employee-extension.zip",
    )
