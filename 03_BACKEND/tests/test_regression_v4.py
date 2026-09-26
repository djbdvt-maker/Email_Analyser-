"""
V4.1 Regression Tests
=====================
Tests covering conclusion generator verdicts, verdict persistence,
role enforcement, async analysis, artifact upload, audit trail, and
detail response truthfulness.
"""
import json
import io

from app.models import UserRole
from tests.conftest import (
    auth_headers,
    _make_user,
    create_investigation,
    create_run,
    internal_service_headers,
)


# -------------------------------------------------------- local helpers --

def _create_finding(client, user, inv_id, run_id, **overrides):
    body = {
        "category": "Content",
        "qualification_code": "FINANCIAL_REQUEST",
        "qualification_version": "reg-v1",
        "strength": "Moderate",
        "analysis_run_id": run_id,
        "normalized_subject_or_target": "target-1",
        "claim_signature": "payment_transfer_request",
        "supporting_fact_ids": [],
        "supporting_text": "some grounded text",
        "produced_by": "deterministic",
    }
    body.update(overrides)
    resp = client.post(
        f"/api/v1/investigations/{inv_id}/findings",
        json=body,
        headers=internal_service_headers(user),
    )
    assert resp.status_code == 201, resp.json()
    return resp


def _advance_to_scoring(client, user, inv_id, run_id):
    for target in ("PARSING", "ANALYZING", "SCORING"):
        client.post(
            f"/api/v1/investigations/{inv_id}/analysis-runs/{run_id}/status",
            json={"status": target},
            headers=auth_headers(user),
        )


def _score(client, user, inv_id, run_id):
    return client.post(
        f"/api/v1/investigations/{inv_id}/analysis-runs/{run_id}/score",
        headers=auth_headers(user),
    )


# ------------------------------------------------ conclusion generator --

def test_conclusion_clean_verdict(client, user):
    """Zero findings → score 0, severity LOW, verdict BENIGN."""
    inv = create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    _advance_to_scoring(client, user, inv["id"], run["id"])

    resp = _score(client, user, inv["id"], run["id"])
    assert resp.status_code == 201
    body = resp.json()
    assert body["total_score"] == 0
    assert body["severity"] == "LOW"
    assert body["verdict"] == "BENIGN"
    assert body["one_line_explanation"] is not None
    assert body["why_explanation"] is not None


def test_conclusion_cf02_bec(client, user):
    """EXECUTIVE_IMPERSONATION + FINANCIAL_REQUEST → CF-02, SUSPICIOUS."""
    inv = create_investigation(client, user)
    run = create_run(client, user, inv["id"])

    _create_finding(
        client, user, inv["id"], run["id"],
        category="Identity",
        qualification_code="EXECUTIVE_IMPERSONATION",
        claim_signature="executive_display_name_claim",
        strength="Moderate",
    )
    _create_finding(
        client, user, inv["id"], run["id"],
        category="Social Engineering",
        qualification_code="FINANCIAL_REQUEST",
        claim_signature="payment_transfer_request",
        strength="Moderate",
    )
    _advance_to_scoring(client, user, inv["id"], run["id"])

    resp = _score(client, user, inv["id"], run["id"])
    assert resp.status_code == 201
    body = resp.json()
    assert "CF-02" in body["triggered_floor_codes"]
    assert body["verdict"] == "SUSPICIOUS"


def test_conclusion_weak_finding_is_clean(client, user):
    """Single Weak finding (4 raw pts) → severity LOW, verdict SUSPICIOUS."""
    inv = create_investigation(client, user)
    run = create_run(client, user, inv["id"])

    _create_finding(
        client, user, inv["id"], run["id"],
        strength="Weak",
    )
    _advance_to_scoring(client, user, inv["id"], run["id"])

    resp = _score(client, user, inv["id"], run["id"])
    assert resp.status_code == 201
    body = resp.json()
    assert body["total_score"] == 2
    assert body["severity"] == "LOW"
    assert body["verdict"] == "SUSPICIOUS"


def test_conclusion_low_severity_anomaly(client, user):
    """Moderate findings in two categories totaling 23 raw → severity LOW, SUSPICIOUS."""
    inv = create_investigation(client, user)
    run = create_run(client, user, inv["id"])

    _create_finding(
        client, user, inv["id"], run["id"],
        category="Social Engineering",
        qualification_code="FINANCIAL_REQUEST",
        claim_signature="payment_transfer_request",
        strength="Moderate",
        normalized_subject_or_target="target-content",
    )
    _create_finding(
        client, user, inv["id"], run["id"],
        category="Domain",
        qualification_code="PROTECTED_BRAND_LOOKALIKE_DOMAIN",
        claim_signature="qualified_protected_brand_lookalike",
        strength="Moderate",
        normalized_subject_or_target="target-domain",
    )
    _advance_to_scoring(client, user, inv["id"], run["id"])

    resp = _score(client, user, inv["id"], run["id"])
    assert resp.status_code == 201
    body = resp.json()
    assert body["total_score"] == 14
    assert body["severity"] == "LOW"
    assert body["verdict"] == "SUSPICIOUS"


def test_verdict_persisted_in_score_response(client, user):
    """Score response includes verdict, one_line_explanation, why_explanation."""
    inv = create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    _advance_to_scoring(client, user, inv["id"], run["id"])

    resp = _score(client, user, inv["id"], run["id"])
    assert resp.status_code == 201
    body = resp.json()
    assert "verdict" in body
    assert "one_line_explanation" in body
    assert "why_explanation" in body
    assert body["verdict"] == "BENIGN"
    assert len(body["one_line_explanation"]) > 0
    assert len(body["why_explanation"]) > 0


def test_list_investigations_includes_verdict(client, user):
    """After scoring and completing run, list investigations includes score/severity/verdict."""
    inv = create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    _advance_to_scoring(client, user, inv["id"], run["id"])
    _score(client, user, inv["id"], run["id"])
    # Complete the run so current_analysis_run_id is set
    client.post(
        f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/status",
        json={"status": "COMPLETED"},
        headers=auth_headers(user),
    )

    resp = client.get("/api/v1/investigations", headers=auth_headers(user))
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) >= 1
    found = next(i for i in items if i["id"] == inv["id"])
    assert found["score"] == 0
    assert found["severity"] == "LOW"
    assert found["verdict"] == "BENIGN"


# ----------------------------------------------------- role enforcement --

def test_viewer_cannot_perform_analyst_actions(client, user, db_session, org):
    """VIEWER role cannot confirm_malicious/false_positive/reopen/close."""
    viewer = _make_user(db_session, org, "viewer@acme.test", role=UserRole.VIEWER)
    inv = create_investigation(client, user)
    # Move to UNDER_REVIEW so confirm_malicious is a valid transition
    client.post(
        f"/api/v1/investigations/{inv['id']}/status",
        json={"status": "UNDER_REVIEW"},
        headers=auth_headers(user),
    )

    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/actions",
        json={"action": "confirm_malicious", "note": "test"},
        headers=auth_headers(viewer),
    )
    assert resp.status_code == 403


def test_analyst_can_perform_actions(client, user):
    """ANALYST role can confirm_malicious."""
    inv = create_investigation(client, user)
    client.post(
        f"/api/v1/investigations/{inv['id']}/status",
        json={"status": "UNDER_REVIEW"},
        headers=auth_headers(user),
    )

    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/actions",
        json={"action": "confirm_malicious", "note": "Verified"},
        headers=auth_headers(user),
    )
    assert resp.status_code == 200
    assert resp.json()["action"] == "confirm_malicious"



# --------------------------------------------------- artifact endpoints --

def test_upload_and_list_artifacts(client, user):
    """Upload a file artifact, then list artifacts to verify it appears."""
    inv = create_investigation(client, user)

    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/artifacts",
        files={"file": ("test.eml", b"From: test@example.com\nSubject: Test\n\nBody", "message/rfc822")},
        headers=auth_headers(user),
    )
    assert resp.status_code == 201
    artifact = resp.json()
    assert artifact["original_filename"] == "test.eml"

    list_resp = client.get(
        f"/api/v1/investigations/{inv['id']}/artifacts",
        headers=auth_headers(user),
    )
    assert list_resp.status_code == 200
    artifacts = list_resp.json()
    assert len(artifacts) >= 1
    assert any(a["id"] == artifact["id"] for a in artifacts)


def test_async_analyze_returns_202(client, user):
    """Upload artifact, POST /analyze → 202 with analysis_run_id."""
    inv = create_investigation(client, user)

    # Upload an artifact first
    client.post(
        f"/api/v1/investigations/{inv['id']}/artifacts",
        files={"file": ("test.eml", b"From: test@example.com\nSubject: Test\n\nBody", "message/rfc822")},
        headers=auth_headers(user),
    )

    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/analyze",
        headers=auth_headers(user),
    )
    assert resp.status_code == 202
    body = resp.json()
    assert "investigation_id" in body
    assert "analysis_run_id" in body
    assert body["status"] == "QUEUED"


# ------------------------------------------------------ audit endpoint --

def test_audit_trail_endpoint(client, user):
    """Create investigation, change status, GET /audit returns events."""
    inv = create_investigation(client, user)
    client.post(
        f"/api/v1/investigations/{inv['id']}/status",
        json={"status": "UNDER_REVIEW"},
        headers=auth_headers(user),
    )

    resp = client.get(
        f"/api/v1/investigations/{inv['id']}/audit",
        headers=auth_headers(user),
    )
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) >= 2  # CREATED + STATUS_CHANGED
    actions = [e["action"] for e in events]
    assert "INVESTIGATION_CREATED" in actions
    assert "INVESTIGATION_STATUS_CHANGED" in actions


# ------------------------------------------------ detail truthfulness --

def test_detail_response_no_placeholder_strings(client, user):
    """After scoring, GET /details must NOT contain placeholder/mock text."""
    inv = create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    _advance_to_scoring(client, user, inv["id"], run["id"])
    _score(client, user, inv["id"], run["id"])

    resp = client.get(
        f"/api/v1/investigations/{inv['id']}",
        headers=auth_headers(user),
    )
    assert resp.status_code == 200
    raw = json.dumps(resp.json()).lower()
    for forbidden in ["placeholder", "todo", "hardcoded"]:
        assert forbidden not in raw, f"Detail response contains forbidden string: {forbidden}"

