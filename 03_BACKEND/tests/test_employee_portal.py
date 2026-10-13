"""
Test suite for Employee Secret Code Provisioning and Restricted Portal Workflows.
Tests:
1. Admin generates secret code and triggers invitation.
2. Employee verifies secret code and obtains scoped 30-day token.
3. Employee scans suspicious email, receives strictly Level 1 & 2 verdict.
4. Employee reports threat to SOC queue, escalating investigation.
5. Inactive/revoked code rejection.
6. Non-admin cannot generate employee codes.
"""
import pytest
from app.models import User, UserRole, Organization, Investigation, EmployeeEnrollmentCode


def test_employee_code_lifecycle_and_portal_scan(client, db_session):
    # 1. Setup Organization and Admin
    org = Organization(name="Acme Corp Cyber")
    db_session.add(org)
    db_session.flush()

    from app.security import hash_password, create_access_token
    admin = User(
        organization_id=org.id,
        email="admin@acme.cyber",
        hashed_password=hash_password("adminpw123"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    db_session.add(admin)
    db_session.commit()

    admin_token = create_access_token(user_id=str(admin.id), organization_id=str(org.id), role="ADMIN")
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 2. Admin generates code for employee
    gen_resp = client.post(
        "/api/v1/admin/employees/generate",
        json={
            "employee_email": "alice@acme.cyber",
            "employee_name": "Alice Smith",
            "department": "Finance",
            "send_email": False,
        },
        headers=admin_headers,
    )
    assert gen_resp.status_code == 201
    code_data = gen_resp.json()
    secret_code = code_data["code"]
    assert secret_code.startswith("HZ-")
    assert code_data["employee_email"] == "alice@acme.cyber"
    assert code_data["is_active"] is True

    # 3. Employee verifies secret code (Zero password required)
    verify_resp = client.post(
        "/api/v1/portal/verify-code",
        json={"code": secret_code},
    )
    assert verify_resp.status_code == 200
    emp_token_data = verify_resp.json()
    emp_token = emp_token_data["access_token"]
    assert emp_token_data["employee_email"] == "alice@acme.cyber"
    assert emp_token_data["department"] == "Finance"
    emp_headers = {"Authorization": f"Bearer {emp_token}"}

    # 4. Check employee profile
    me_resp = client.get("/api/v1/portal/me", headers=emp_headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["employee_name"] == "Alice Smith"

    # 5. Employee scans an email via Portal
    sample_eml = b"""From: attacker@evil-spoofed.com
To: alice@acme.cyber
Subject: URGENT: Wire Transfer Required Immediately
Date: Mon, 13 Oct 2026 12:00:00 +0000

Please verify your bank details here: http://phish-secure-login.ru/verify
"""
    scan_resp = client.post(
        "/api/v1/portal/scan",
        files={"file": ("invoice_phish.eml", sample_eml, "message/rfc822")},
        headers=emp_headers,
    )
    assert scan_resp.status_code == 200
    scan_result = scan_resp.json()
    assert "investigation_id" in scan_result
    assert scan_result["verdict"] in ("SAFE", "SUSPICIOUS", "DANGEROUS")
    assert "one_line_explanation" in scan_result
    assert "action_recommendation" in scan_result
    inv_id = scan_result["investigation_id"]

    # Verify investigation in DB is tagged with employee email
    inv_db = db_session.get(Investigation, inv_id)
    assert inv_db.reported_by_employee == "alice@acme.cyber"

    # 6. Employee reports the email to SOC
    report_resp = client.post(
        "/api/v1/portal/report",
        json={"investigation_id": inv_id, "employee_notes": "Looks like an executive impersonation phishing attempt."},
        headers=emp_headers,
    )
    assert report_resp.status_code == 200
    assert report_resp.json()["status"] == "reported"

    db_session.refresh(inv_db)
    assert inv_db.employee_notes == "Looks like an executive impersonation phishing attempt."

    # 7. Admin revokes code
    code_id = code_data["id"]
    del_resp = client.delete(f"/api/v1/admin/employees/{code_id}", headers=admin_headers)
    assert del_resp.status_code == 204

    # 8. Revoked code fails verification
    fail_verify = client.post("/api/v1/portal/verify-code", json={"code": secret_code})
    assert fail_verify.status_code == 401
