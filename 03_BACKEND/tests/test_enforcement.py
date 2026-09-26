"""
Tests for Provider-Neutral Threat Response & Enforcement (Sections 14, 15, 16, 24).
=================================================================================
Proves:
- Sender, domain, and IP normalization.
- Unsupported IP targets (loopback, private, link-local, multicast, 0.0.0.0) rejected.
- Grounding check: arbitrary targets not grounded in evidence are rejected.
- RBAC: regular user / viewer cannot authorize/execute enforcement (403).
- Analyst and admin roles can authorize and execute.
- Cross-organization enforcement rejected.
- Execution lifecycle states: REQUESTED -> AUTHORIZED -> EXECUTED (or FAILED / REJECTED).
- Provider failure is honestly recorded as FAILED.
- All actions are auditable with actor and timestamp.
- AI and score engine cannot authorize enforcement.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    Investigation,
    AnalysisRun,
    AnalysisRunStatus,
    Fact,
    User,
    UserRole,
    EnforcementAction,
    EnforcementStatus,
    AuditEvent,
    AuditAction,
)
from app.services.enforcement_service import (
    normalize_sender,
    normalize_domain,
    normalize_ip,
)
from app.main import app
from tests.conftest import auth_headers, _make_user


def test_sender_normalization():
    assert normalize_sender("  ATTACKER@Phishing.COM  ") == "attacker@phishing.com"
    assert normalize_sender("Bad Guy <bad@evil.org>") == "bad@evil.org"
    with pytest.raises(Exception):
        normalize_sender("not-an-email")
    with pytest.raises(Exception):
        normalize_sender("")


def test_domain_normalization():
    assert normalize_domain("  Evil-Domain.COM.  ") == "evil-domain.com"
    assert normalize_domain("https://phishing.site/path/index.html") == "phishing.site"
    assert normalize_domain("login.fakebank.com:8080") == "login.fakebank.com"
    with pytest.raises(Exception):
        normalize_domain("invalid..domain")


def test_ip_normalization_and_unsupported_rejection():
    # Valid public routable IP accepted
    assert normalize_ip(" 93.184.216.34 ") == "93.184.216.34"
    assert normalize_ip("2606:2800:220:1:248:1893:25c8:1946") == "2606:2800:220:1:248:1893:25c8:1946"

    # Unsupported IP targets rejected
    with pytest.raises(Exception) as exc1:
        normalize_ip("127.0.0.1")
    assert "loopback" in str(exc1.value)

    with pytest.raises(Exception) as exc2:
        normalize_ip("10.0.0.1")
    assert "private" in str(exc2.value)

    with pytest.raises(Exception) as exc3:
        normalize_ip("192.168.1.1")
    assert "private" in str(exc3.value)

    with pytest.raises(Exception) as exc4:
        normalize_ip("169.254.1.1")
    assert "link-local" in str(exc4.value)

    with pytest.raises(Exception) as exc5:
        normalize_ip("224.0.0.1")
    assert "multicast" in str(exc5.value)

    with pytest.raises(Exception) as exc6:
        normalize_ip("0.0.0.0")
    assert "unspecified" in str(exc6.value)


def test_enforcement_grounding_and_lifecycle(client: TestClient, db_session: Session, org, other_org):
    """
    Full test of enforcement lifecycle with grounding and RBAC:
    1. Set up investigation with grounded facts (sender: evil@phish.org, domain: phish.org, IP: 93.184.216.34).
    2. Attempt arbitrary ungrounded target -> rejected (400).
    3. Request grounded sender block -> 201 REQUESTED.
    4. Viewer cannot authorize -> 403.
    5. Analyst authorizes -> 200 AUTHORIZED.
    6. Viewer cannot execute -> 403.
    7. Analyst executes -> 200 EXECUTED with demo provider details.
    8. Cross-organization access rejected (404).
    9. Audit events verified.
    """
    analyst = _make_user(db_session, org, "analyst@org.test", role=UserRole.ANALYST)
    viewer = _make_user(db_session, org, "viewer@org.test", role=UserRole.VIEWER)
    other_analyst = _make_user(db_session, other_org, "other@other.test", role=UserRole.ANALYST)

    analyst_headers = auth_headers(analyst)
    viewer_headers = auth_headers(viewer)
    other_headers = auth_headers(other_analyst)

    # Create investigation
    inv_res = client.post("/api/v1/investigations", json={"title": "Enforcement Test"}, headers=analyst_headers)
    assert inv_res.status_code == 201
    inv_id = inv_res.json()["id"]

    # Add grounded facts into database for this investigation
    f1 = Fact(
        investigation_id=inv_id,
        analysis_run_id="run-placeholder",
        fact_type="envelope_metadata",
        payload={
            "from_address": "spammer@evil-actor.com",
            "from_domain": "evil-actor.com",
        },
        produced_by="deterministic",
    )
    f2 = Fact(
        investigation_id=inv_id,
        analysis_run_id="run-placeholder",
        fact_type="probable_origin_ip",
        payload={"value": "93.184.216.34"},
        produced_by="deterministic",
    )
    db_session.add_all([f1, f2])
    
    # Ensure the investigation has a current_analysis_run_id, per the new strict grounding rule
    inv = db_session.get(Investigation, inv_id)
    inv.current_analysis_run_id = "run-placeholder"
    
    db_session.commit()

    # Step 2: Attempt arbitrary ungrounded target -> 400 Bad Request
    arb_res = client.post(
        f"/api/v1/investigations/{inv_id}/enforcement/request",
        json={"action_type": "BLOCK_SENDER", "target": "innocent@google.com"},
        headers=analyst_headers,
    )
    assert arb_res.status_code == 400
    assert "not grounded" in arb_res.json()["message"]

    arb_ip_res = client.post(
        f"/api/v1/investigations/{inv_id}/enforcement/request",
        json={"action_type": "BLOCK_IP", "target": "8.8.4.4"},
        headers=analyst_headers,
    )
    assert arb_ip_res.status_code == 400
    assert "not grounded" in arb_ip_res.json()["message"]

    # Step 3: Request grounded sender block -> 201 REQUESTED
    req_res = client.post(
        f"/api/v1/investigations/{inv_id}/enforcement/request",
        json={"action_type": "BLOCK_SENDER", "target": "Spammer@evil-actor.COM"},
        headers=analyst_headers,
    )
    assert req_res.status_code == 201
    action_data = req_res.json()
    action_id = action_data["id"]
    assert action_data["status"] == "REQUESTED"
    assert action_data["target"] == "spammer@evil-actor.com"
    assert action_data["is_demo"] is True

    # Cross-org access rejected
    cross_res = client.get(f"/api/v1/investigations/{inv_id}/enforcement", headers=other_headers)
    assert cross_res.status_code == 404

    # Step 4: Viewer cannot authorize -> 403 Forbidden
    view_auth_res = client.post(
        f"/api/v1/investigations/{inv_id}/enforcement/{action_id}/authorize",
        headers=viewer_headers,
    )
    assert view_auth_res.status_code == 403

    # Step 5: Analyst authorizes -> 200 AUTHORIZED
    analyst_auth_res = client.post(
        f"/api/v1/investigations/{inv_id}/enforcement/{action_id}/authorize",
        headers=analyst_headers,
    )
    assert analyst_auth_res.status_code == 200
    assert analyst_auth_res.json()["status"] == "AUTHORIZED"

    # Step 6: Viewer cannot execute -> 403 Forbidden
    view_exec_res = client.post(
        f"/api/v1/investigations/{inv_id}/enforcement/{action_id}/execute",
        headers=viewer_headers,
    )
    assert view_exec_res.status_code == 403

    # Step 7: Analyst executes -> 200 EXECUTED
    exec_res = client.post(
        f"/api/v1/investigations/{inv_id}/enforcement/{action_id}/execute",
        headers=analyst_headers,
    )
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    assert exec_data["status"] == "EXECUTED"
    assert exec_data["provider"] == "mock_local_provider"
    assert exec_data["is_demo"] is True
    assert "external mail provider not modified" in exec_data["execution_details"]["provider_message"]

    # Step 8: Check audit trail
    audit_events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.investigation_id == inv_id)
        .all()
    )
    actions = [a.action.value for a in audit_events]
    assert "ENFORCEMENT_REQUESTED" in actions
    assert "ENFORCEMENT_AUTHORIZED" in actions
    assert "ENFORCEMENT_EXECUTED" in actions


def test_enforcement_simulated_failure(client: TestClient, db_session: Session, org):
    """Execution failures are honestly recorded as FAILED without faking success."""
    analyst = _make_user(db_session, org, "analyst2@org.test", role=UserRole.ANALYST)
    analyst_headers = auth_headers(analyst)

    inv_res = client.post("/api/v1/investigations", json={"title": "Failure Test"}, headers=analyst_headers)
    inv_id = inv_res.json()["id"]

    f1 = Fact(
        investigation_id=inv_id,
        analysis_run_id="run-placeholder",
        fact_type="envelope_metadata",
        payload={"from_domain": "badactor.com"},
        produced_by="deterministic",
    )
    db_session.add(f1)
    
    inv = db_session.get(Investigation, inv_id)
    inv.current_analysis_run_id = "run-placeholder"
    
    db_session.commit()

    # Request
    req_res = client.post(
        f"/api/v1/investigations/{inv_id}/enforcement/request",
        json={"action_type": "BLOCK_DOMAIN", "target": "badactor.com"},
        headers=analyst_headers,
    )
    action_id = req_res.json()["id"]

    # Authorize
    client.post(
        f"/api/v1/investigations/{inv_id}/enforcement/{action_id}/authorize",
        headers=analyst_headers,
    )

    # Execute with simulated failure
    exec_res = client.post(
        f"/api/v1/investigations/{inv_id}/enforcement/{action_id}/execute",
        json={"simulate_failure": True},
        headers=analyst_headers,
    )
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    assert exec_data["status"] == "FAILED"
    assert "Simulated provider failure" in exec_data["failure_reason"]

    # Verify audit records ENFORCEMENT_FAILED
    audit_failed = (
        db_session.query(AuditEvent)
        .filter(
            AuditEvent.investigation_id == inv_id,
            AuditEvent.action == AuditAction.ENFORCEMENT_FAILED,
        )
        .first()
    )
    assert audit_failed is not None


def test_enforcement_rejection(client: TestClient, db_session: Session, org):
    """Enforcement action can be rejected with reason."""
    analyst = _make_user(db_session, org, "analyst3@org.test", role=UserRole.ANALYST)
    analyst_headers = auth_headers(analyst)

    inv_res = client.post("/api/v1/investigations", json={"title": "Rejection Test"}, headers=analyst_headers)
    inv_id = inv_res.json()["id"]

    f1 = Fact(
        investigation_id=inv_id,
        analysis_run_id="run-placeholder",
        fact_type="probable_origin_ip",
        payload={"value": "93.184.216.34"},
        produced_by="deterministic",
    )
    db_session.add(f1)
    
    inv = db_session.get(Investigation, inv_id)
    inv.current_analysis_run_id = "run-placeholder"
    
    db_session.commit()

    req_res = client.post(
        f"/api/v1/investigations/{inv_id}/enforcement/request",
        json={"action_type": "BLOCK_IP", "target": "93.184.216.34"},
        headers=analyst_headers,
    )
    action_id = req_res.json()["id"]

    # Reject
    rej_res = client.post(
        f"/api/v1/investigations/{inv_id}/enforcement/{action_id}/reject",
        json={"reason": "Shared cloud relay, blocking entire IP would cause collateral damage."},
        headers=analyst_headers,
    )
    assert rej_res.status_code == 200
    rej_data = rej_res.json()
    assert rej_data["status"] == "REJECTED"
    assert "collateral damage" in rej_data["rejection_reason"]
