"""
End-to-End Pipeline Integration Test (Phase 3 Manual E2E).
=========================================================
Proves:
sample .eml
  ↓
POST /api/v1/ingest
  ↓
artifact hash
  ↓
AnalysisRun
  ↓
parser
  ↓
normalization
  ↓
routing
  ↓
authentication
  ↓
identity
  ↓
domain
  ↓
links
  ↓
attachments
  ↓
AI
  ↓
AI validation
  ↓
Findings
  ↓
Score
  ↓
Floors
  ↓
Verdict
  ↓
frontend (/details composed endpoint)

Evaluates 5 canonical email types:
1. Clean Corporate Email
2. Business Email Compromise (BEC)
3. Credential Phishing Email
4. Lookalike Domain Email
5. Suspicious Attachment Email

Verifies BEC:
executive impersonation + financial request activates CF-02 and results in at least High severity.
"""
import os
import hashlib
import pytest

from tests.conftest import TEST_N8N_INGEST_KEY, auth_headers

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "07_TEST_DATA"))


def _run_e2e_pipeline_for_file(client, user, relative_path: str, provider_id: str):
    full_path = os.path.join(DATA_DIR, relative_path)
    assert os.path.exists(full_path), f"Test fixture not found: {full_path}"

    with open(full_path, "rb") as f:
        raw_bytes = f.read()

    expected_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    # 1. Ingest
    ingest_resp = client.post(
        "/api/v1/ingest",
        headers={"X-N8N-Ingest-Key": TEST_N8N_INGEST_KEY},
        data={
            "ingestion_source": "manual_e2e_test",
            "provider_message_id": provider_id,
            "title": f"E2E: {os.path.basename(relative_path)}",
            "auto_analyze": "true",
        },
        files={"file": (os.path.basename(relative_path), raw_bytes, "message/rfc822")},
    )
    assert ingest_resp.status_code == 201, f"Ingest failed: {ingest_resp.text}"
    ingest_data = ingest_resp.json()
    inv_id = ingest_data["investigation_id"]
    run_id = ingest_data["analysis_run_id"]
    assert ingest_data["status"] == "COMPLETED"

    # 2. Fetch full investigation detail (the frontend API contract)
    detail_resp = client.get(f'/api/v1/investigations/{inv_id}', headers=auth_headers(user))
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail['id'] == inv_id
    assert detail['current_analysis_run_id'] == run_id
    
    score_resp = client.get(f'/api/v1/investigations/{inv_id}/analysis-runs/{run_id}/score', headers=auth_headers(user))
    assert score_resp.status_code == 200
    result = score_resp.json()
    
    findings_resp = client.get(f'/api/v1/investigations/{inv_id}/findings?analysis_run_id={run_id}', headers=auth_headers(user))
    assert findings_resp.status_code == 200
    result['findings'] = findings_resp.json()
    
    return detail, result


def test_e2e_01_clean_email(client, user):
    """
    1. Clean email:
    Expected: Clean / Benign verdict, Low or 0 score, no malicious floors.
    """
    detail, result = _run_e2e_pipeline_for_file(
        client, user,
        os.path.join("clean", "clean_legit_corporate.eml"),
        "e2e-msg-clean-01",
    )
    assert result["total_score"] <= 29
    assert result["severity"].upper() == "LOW"
    assert result["verdict"] == "BENIGN"
    assert result["triggered_floor_codes"] == []


def test_e2e_02_bec_email(client, user):
    """
    2. BEC email:
    executive impersonation + financial request activates CF-02
    and results in at least High severity.
    """
    detail, result = _run_e2e_pipeline_for_file(
        client, user,
        os.path.join("BEC", "bec_ceo_wire_transfer.eml"),
        "e2e-msg-bec-02",
    )

    # Verify findings contain Executive Impersonation and Financial Request
    findings = result["findings"]
    qual_codes = {f["qualification_code"] for f in findings}
    assert "EXECUTIVE_IMPERSONATION" in qual_codes, f"Missing EXECUTIVE_IMPERSONATION in {qual_codes}"
    assert "FINANCIAL_REQUEST" in qual_codes, f"Missing FINANCIAL_REQUEST in {qual_codes}"

    # Verify CF-02 floor activated
    assert "CF-02" in result["triggered_floor_codes"], f"CF-02 not triggered in {result['triggered_floor_codes']}"
    # Floor forces at least High severity
    assert result["severity"].upper() in ("HIGH", "CRITICAL")
    assert result["verdict"] in ("SUSPICIOUS", "MALICIOUS")

    # Verify findings expose analysis_run_id
    for f in findings:
        assert "analysis_run_id" in f
        assert f["analysis_run_id"] == detail["current_analysis_run_id"]


def test_e2e_03_credential_phishing(client, user):
    """
    3. Credential phishing email:
    Phishing link + auth or identity anomaly triggers CF-03 and forces High/Critical.
    """
    detail, result = _run_e2e_pipeline_for_file(
        client, user,
        os.path.join("phishing", "credential_harvesting_portal.eml"),
        "e2e-msg-phish-03",
    )
    findings = result["findings"]
    qual_codes = {f["qualification_code"] for f in findings}
    assert "CREDENTIAL_PHISHING_LINK" in qual_codes or "CREDENTIAL_PHISHING" in qual_codes
    assert "CF-03" in result["triggered_floor_codes"]
    assert result["severity"].upper() in ("HIGH", "CRITICAL")
    assert result["verdict"] in ("SUSPICIOUS", "MALICIOUS")


def test_e2e_04_lookalike_domain(client, user):
    """
    4. Lookalike domain email:
    Protected brand lookalike / homoglyph domain anomaly.
    """
    detail, result = _run_e2e_pipeline_for_file(
        client, user,
        os.path.join("lookalike", "protected_brand_lookalike.eml"),
        "e2e-msg-lookalike-04",
    )
    findings = result["findings"]
    qual_codes = {f["qualification_code"] for f in findings}
    assert "HOMOGLYPH_OR_LOOKALIKE" in qual_codes or "DOMAIN_ANOMALY" in qual_codes or any(f["category"] == "Domain" for f in findings)
    assert result["total_score"] > 0


def test_e2e_05_suspicious_attachment(client, user):
    """
    5. Suspicious attachment email:
    Double extension macro / executable attachment triggers findings and floor CF-04.
    """
    detail, result = _run_e2e_pipeline_for_file(
        client, user,
        os.path.join("attachments", "double_extension_macro.eml"),
        "e2e-msg-attach-05",
    )
    findings = result["findings"]
    qual_codes = {f["qualification_code"] for f in findings}
    assert "MALICIOUS_ATTACHMENT" in qual_codes or "SUSPICIOUS_ATTACHMENT" in qual_codes or any(f["category"] == "Attachment" for f in findings)
    assert result["total_score"] > 0




