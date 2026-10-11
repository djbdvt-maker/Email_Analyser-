"""
Tests for Chrome Extension Workflow Integration.
================================================
Verifies that the exact API contract used by the Chrome Extension
(HopZeroClient in 07_EXTENSION/src/api/hopzero_client.js and popup.js)
operates end-to-end against the backend:

1. Extension User Login: POST /api/v1/auth/login (OAuth2 form-encoded)
2. Extension Email Ingest: POST /api/v1/ingest
   - ingestion_source = "gmail_extension_api"
   - provider_message_id = "gmail-msg-001"
   - auto_analyze = "true"
   - raw .eml file upload
3. Investigation & AnalysisRun lifecycle polling:
   GET /api/v1/investigations/{id}/analysis-runs/{run_id}
4. Score & Verdict Retrieval for Extension Popup badge:
   GET /api/v1/investigations/{id}/analysis-runs/{run_id}/score
   - total_score, severity, verdict, conclusion_text
5. Findings Inspection:
   GET /api/v1/investigations/{id}/findings?analysis_run_id={run_id}
6. User Feedback / Dispute from Popup:
   POST /api/v1/investigations/{id}/feedback
7. Re-analysis Run Polling & Execution.
"""
import io
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import UserRole
from tests.conftest import _make_user

SAMPLE_GMAIL_EML = b"""From: "Security Alerts" <alert@chase-banking-portal.com>
To: victim@example.com
Subject: Urgent: Verify Your Online Banking Access
Date: Sat, 11 Oct 2026 12:00:00 +0000
Message-ID: <gmail-ext-test-001@chase-banking-portal.com>
Received: from mail.chase-banking-portal.com (mail.chase-banking-portal.com [198.51.100.42])
        by mx.google.com with ESMTPS id gmail123;
        Sat, 11 Oct 2026 12:00:01 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Your banking access has been temporarily restricted.
Please click http://login.chase-banking-portal.com/verify to restore access.
"""


def test_extension_email_checker_workflow(client: TestClient, db_session: Session, org):
    """
    Simulates the exact API calls made by HopZero's Chrome Extension
    when a user opens an email in Gmail and inspects it via popup.js.
    """
    # 1. Setup user account for the extension
    user_email = "analyst_ext@bank.test"
    user_pw = "password123"
    user = _make_user(db_session, org, user_email, role=UserRole.ANALYST)

    # 2. Step 1 of HopZeroClient: login()
    login_res = client.post(
        "/api/v1/auth/login",
        data={"username": user_email, "password": user_pw},
    )
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    token_data = login_res.json()
    assert "access_token" in token_data
    auth_header = {"Authorization": f"Bearer {token_data['access_token']}"}

    # 3. Step 2 of HopZeroClient: ingestEmail()
    # Matches FormData construction in hopzero_client.js:ingestEmail
    ingest_form = {
        "ingestion_source": "gmail_extension_api",
        "provider_message_id": "gmail-msg-001",
        "title": "Ext Ingestion: gmail-msg-001",
        "auto_analyze": "true",
    }
    ingest_files = {
        "file": ("gmail-msg-001.eml", io.BytesIO(SAMPLE_GMAIL_EML), "message/rfc822"),
    }
    ingest_res = client.post(
        "/api/v1/ingest",
        data=ingest_form,
        files=ingest_files,
        headers=auth_header,
    )
    assert ingest_res.status_code in (200, 201), f"Ingest failed: {ingest_res.text}"
    ingest_data = ingest_res.json()

    assert "investigation_id" in ingest_data
    assert "analysis_run_id" in ingest_data
    inv_id = ingest_data["investigation_id"]
    run_id = ingest_data["analysis_run_id"]

    # 4. Step 3 of HopZeroClient: getAnalysisRun()
    run_res = client.get(
        f"/api/v1/investigations/{inv_id}/analysis-runs/{run_id}",
        headers=auth_header,
    )
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["status"] == "COMPLETED"

    # 5. Step 4 of HopZeroClient: getScore()
    # popup.js expects scoreData.total_score, scoreData.severity, scoreData.verdict, scoreData.conclusion_text
    score_res = client.get(
        f"/api/v1/investigations/{inv_id}/analysis-runs/{run_id}/score",
        headers=auth_header,
    )
    assert score_res.status_code == 200
    score_data = score_res.json()

    assert "total_score" in score_data
    assert "severity" in score_data
    assert "verdict" in score_data
    assert "conclusion_text" in score_data
    assert score_data["total_score"] >= 0
    assert score_data["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert score_data["verdict"] in ("BENIGN", "SUSPICIOUS", "MALICIOUS", "INDETERMINATE")

    # 6. Step 5 of HopZeroClient: getFindings()
    # popup.js lists forensic findings for the run
    findings_res = client.get(
        f"/api/v1/investigations/{inv_id}/findings?analysis_run_id={run_id}",
        headers=auth_header,
    )
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert isinstance(findings, list)
    assert len(findings) > 0

    # 7. Step 6 of HopZeroClient: submitFeedback()
    # popup.js allows reporting phishing/spam or disputing analysis
    feedback_payload = {
        "source_analysis_run_id": run_id,
        "feedback_type": "PHISHING_REPORTED",
        "note": "Reported as phishing via Chrome Extension popup",
    }
    fb_res = client.post(
        f"/api/v1/investigations/{inv_id}/feedback",
        json=feedback_payload,
        headers=auth_header,
    )
    assert fb_res.status_code in (200, 201)
    fb_data = fb_res.json()
    assert "new_analysis_run_id" in fb_data
    new_run_id = fb_data["new_analysis_run_id"]
    assert new_run_id != run_id

    # 8. Step 7 of HopZeroClient: pollRun() on new run
    new_run_res = client.get(
        f"/api/v1/investigations/{inv_id}/analysis-runs/{new_run_id}",
        headers=auth_header,
    )
    assert new_run_res.status_code == 200
    assert new_run_res.json()["status"] == "COMPLETED"
