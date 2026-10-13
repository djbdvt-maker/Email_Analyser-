"""
Tests verifying remediations for the application security audit findings:
1. Path traversal protection on SPA static file routes.
2. Rate limiting on the Secret Code verification endpoint.
3. Bounded memory limits on employee email uploads (>25MB rejected with 413).
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models import EmployeeEnrollmentCode, Organization, User, UserRole
from app.security import hash_password


from app.models import EmployeeEnrollmentCode
from fastapi import HTTPException


@pytest.fixture
def test_employee_code(db_session, org, user):
    code = EmployeeEnrollmentCode(
        organization_id=org.id,
        created_by_user_id=user.id,
        code="HZ-AUDI-T001",
        employee_email="employee@test.local",
        is_active=True,
    )
    db_session.add(code)
    db_session.commit()
    return code


from app.api.v1.routes_auth import _LOGIN_ATTEMPTS


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    _LOGIN_ATTEMPTS.clear()
    yield
    _LOGIN_ATTEMPTS.clear()


def test_spa_path_traversal_is_blocked(client):
    # Arbitrary file traversal paths must not be served
    for path in ["/../../storage/hopzero.db", "/../app/main.py", "/etc/passwd"]:
        resp = client.get(path)
        assert resp.status_code == 404


def test_verify_secret_code_rate_limiting(client):
    status_codes = []
    for _ in range(20):
        resp = client.post("/api/v1/portal/verify-code", json={"code": "HZ-INVA-LID1"})
        status_codes.append(resp.status_code)

    assert 429 in status_codes, f"Expected 429 Too Many Requests in attempts: {status_codes}"


def test_oversized_upload_rejected_with_413(client, test_employee_code):
    _LOGIN_ATTEMPTS.clear()
    auth_resp = client.post("/api/v1/portal/verify-code", json={"code": test_employee_code.code})
    assert auth_resp.status_code == 200
    token = auth_resp.json()["access_token"]

    oversized_pasted = "A" * (26 * 1024 * 1024)
    resp = client.post(
        "/api/v1/portal/scan",
        headers={"Authorization": f"Bearer {token}"},
        data={"raw_content": oversized_pasted},
    )
    assert resp.status_code == 413
    assert "exceeds maximum allowable size" in resp.json()["message"]


def test_http_security_headers_present(client):
    """Verifies that OWASP-compliant HTTP security headers are injected into responses."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "camera=()" in resp.headers.get("Permissions-Policy", "")

    # API endpoints must enforce Cache-Control: no-store
    api_resp = client.get("/api/v1/system/version")
    assert "no-store" in api_resp.headers.get("Cache-Control", "")


def test_evidence_endpoint_oversized_upload_rejected(client, user, org, db_session):
    """Verifies that evidence uploads over 25MB are rejected with 413."""
    from tests.conftest import auth_headers
    from app.models import Investigation, InvestigationStatus

    inv = Investigation(
        organization_id=org.id,
        title="Upload Size Test",
        created_by_user_id=user.id,
        status=InvestigationStatus.AWAITING_ANALYSIS,
    )
    db_session.add(inv)
    db_session.commit()
    db_session.refresh(inv)
    inv_id = str(inv.id)

    headers = auth_headers(user)
    # Send >25MB file
    oversized = b"X" * (26 * 1024 * 1024)
    resp = client.post(
        f"/api/v1/investigations/{inv_id}/evidence",
        headers=headers,
        files={"file": ("huge.eml", oversized, "message/rfc822")},
    )
    assert resp.status_code == 413
    assert "ARTIFACT_TOO_LARGE" in resp.json()["message"]


def test_websocket_unauthenticated_connection_rejected(client):
    """Verifies that WebSocket connections without a valid token are immediately closed."""
    with pytest.raises(Exception):
        with client.websocket_connect("/api/v1/ws") as ws:
            pass


