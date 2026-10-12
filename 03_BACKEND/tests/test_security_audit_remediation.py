import io
import pytest
from app.models import UserRole, Investigation, InvestigationStatus
from app.security import get_current_user
from app.api.v1.routes_sandbox import _validate_safe_sandbox_url
from app.api.v1.routes_auth import _LOGIN_ATTEMPTS, _MAX_ATTEMPTS
from hopzero.core.licensing import get_trusted_public_keys, OFFICIAL_LICENSE_PUBLIC_KEYS
from hopzero.core.signatures import get_trusted_release_keys, OFFICIAL_RELEASE_PUBLIC_KEYS
from tests.conftest import auth_headers, _make_user


def test_ed25519_trusted_public_keys_env_override(monkeypatch):
    """Verify HOPZERO_TRUSTED_LICENSE_PUBLIC_KEYS and RELEASE keys can be extended via env."""
    custom_key = "1" * 64
    monkeypatch.setenv("HOPZERO_TRUSTED_LICENSE_PUBLIC_KEYS", custom_key)
    monkeypatch.setenv("HOPZERO_TRUSTED_RELEASE_PUBLIC_KEYS", custom_key)

    trusted_lic = get_trusted_public_keys()
    trusted_rel = get_trusted_release_keys()

    assert bytes.fromhex(custom_key) in trusted_lic
    assert bytes.fromhex(custom_key) in trusted_rel
    assert len(OFFICIAL_LICENSE_PUBLIC_KEYS) > 0
    assert len(OFFICIAL_RELEASE_PUBLIC_KEYS) > 0


def test_ssrf_url_validation_blocks_private_and_local():
    """Verify SSRF validation strictly rejects private IP space, loopback, file, and cloud metadata."""
    unsafe_urls = [
        "file:///etc/passwd",
        "ftp://malicious.test/data",
        "http://localhost/admin",
        "http://localhost:8000/internal",
        "http://127.0.0.1:8080",
        "http://127.0.0.1/status",
        "http://10.0.0.1/metadata",
        "http://172.16.0.1/secret",
        "http://192.168.1.1/router",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/internal",
    ]
    for url in unsafe_urls:
        with pytest.raises(Exception):
            _validate_safe_sandbox_url(url)

    # Valid external URLs must pass
    safe_urls = [
        "https://example.com/login",
        "http://93.184.216.34/page",
    ]
    for url in safe_urls:
        _validate_safe_sandbox_url(url)


def test_sandbox_screenshot_endpoint_ssrf_rejection(client, user):
    """GET /api/v1/sandbox/screenshot rejects SSRF payloads with 400 Bad Request."""
    resp = client.get(
        "/api/v1/sandbox/screenshot?url=http://169.254.169.254/latest/meta-data/",
        headers=auth_headers(user),
    )
    assert resp.status_code == 400
    assert "Prohibited target" in resp.json()["message"]


def test_evidence_path_traversal_sanitization(client, db_session, org, user):
    """Evidence upload sanitizes path traversal characters in filename."""
    from app.models import Artifact
    inv = Investigation(
        organization_id=org.id,
        title="Traversal Test Inv",
        created_by_user_id=user.id,
        status=InvestigationStatus.AWAITING_ANALYSIS,
    )
    db_session.add(inv)
    db_session.commit()
    db_session.refresh(inv)

    file_payload = ("../../../../evil.txt", io.BytesIO(b"malicious payload"), "text/plain")
    resp = client.post(
        f"/api/v1/investigations/{inv.id}/evidence",
        headers=auth_headers(user),
        files={"file": file_payload},
        data={"evidence_type": "email_headers", "label": "Path Traversal Test"},
    )
    assert resp.status_code == 201
    # Check that the persisted artifact in the DB sanitizes the file path
    art = db_session.query(Artifact).filter(Artifact.investigation_id == inv.id).first()
    assert art is not None
    assert ".." not in art.storage_path
    assert "evil.txt" in art.storage_path


def test_login_rate_limiting_triggers_429(client, user):
    """POST /api/v1/auth/login blocks brute-force attempts after threshold with 429."""
    _LOGIN_ATTEMPTS.clear()

    # Perform requests up to the limit
    for _ in range(_MAX_ATTEMPTS):
        resp = client.post(
            "/api/v1/auth/login",
            data={"username": user.email, "password": "wrongpassword"},
        )
        assert resp.status_code in (401, 200)

    # Attempt number (_MAX_ATTEMPTS + 1) should be rate-limited
    resp_blocked = client.post(
        "/api/v1/auth/login",
        data={"username": user.email, "password": "wrongpassword"},
    )
    assert resp_blocked.status_code == 429
    assert "Too many authentication attempts" in resp_blocked.json()["message"]
    _LOGIN_ATTEMPTS.clear()


def test_audit_log_access_role_gating(client, db_session, org):
    """Standard USER role is denied access to investigation audit logs; ANALYST and ADMIN allowed."""
    user_regular = _make_user(db_session, org, "regular@acme.test", role=UserRole.USER)
    user_analyst = _make_user(db_session, org, "sec_analyst@acme.test", role=UserRole.ANALYST)
    user_admin = _make_user(db_session, org, "sec_admin@acme.test", role=UserRole.ADMIN)

    inv = Investigation(
        organization_id=org.id,
        title="Audit Role Test",
        created_by_user_id=user_analyst.id,
        status=InvestigationStatus.AWAITING_ANALYSIS,
    )
    db_session.add(inv)
    db_session.commit()
    db_session.refresh(inv)

    # USER should get 403 Forbidden
    resp_user = client.get(
        f"/api/v1/investigations/{inv.id}/audit",
        headers=auth_headers(user_regular),
    )
    assert resp_user.status_code == 403

    # ANALYST should get 200 OK
    resp_analyst = client.get(
        f"/api/v1/investigations/{inv.id}/audit",
        headers=auth_headers(user_analyst),
    )
    assert resp_analyst.status_code == 200

    # ADMIN should get 200 OK
    resp_admin = client.get(
        f"/api/v1/investigations/{inv.id}/audit",
        headers=auth_headers(user_admin),
    )
    assert resp_admin.status_code == 200


def test_chain_of_custody_export_role_gating(client, db_session, org):
    """Standard USER role is denied access to chain-of-custody export; ANALYST and ADMIN allowed."""
    user_regular = _make_user(db_session, org, "export_user@acme.test", role=UserRole.USER)
    user_analyst = _make_user(db_session, org, "export_analyst@acme.test", role=UserRole.ANALYST)

    inv = Investigation(
        organization_id=org.id,
        title="CoC Export Test",
        created_by_user_id=user_analyst.id,
        status=InvestigationStatus.AWAITING_ANALYSIS,
    )
    db_session.add(inv)
    db_session.commit()
    db_session.refresh(inv)

    # USER should get 403 Forbidden
    resp_user = client.get(
        f"/api/v1/investigations/{inv.id}/export",
        headers=auth_headers(user_regular),
    )
    assert resp_user.status_code == 403

    # ANALYST passes the role check (does not get 403)
    resp_analyst = client.get(
        f"/api/v1/investigations/{inv.id}/export",
        headers=auth_headers(user_analyst),
    )
    assert resp_analyst.status_code != 403


def test_api_key_role_assigned_as_analyst(monkeypatch, db_session, org):
    """Extension/service API key authentication defaults to ANALYST role (least privilege) instead of ADMIN."""
    import app.security
    monkeypatch.setattr(app.security.settings, "hopzero_api_key", "test-api-key-999")

    user = get_current_user(token="test-api-key-999", db=db_session)
    assert user.role == UserRole.ANALYST
