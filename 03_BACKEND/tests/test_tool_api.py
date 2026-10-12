"""
Tests for Tool-Facing API & BotChain Tool Manifest (HZ3).
=========================================================

Verifies:
1. GET /tool-manifest and GET /version contract compliance.
2. Clean, stable operationId values across the entire OpenAPI schema.
3. Coarse operation: POST /api/v1/tool/analyze-email (synchronous pipeline execution).
4. Default include_body=false prevents leaking body text into bot context.
5. Untrusted content markers on raw email string fields.
6. Fine operations: inspect_headers, extract_indicators, explain_score, get_investigation summary.
"""
import io
import os
import pytest

from app.main import app
from app.qualification_registry import REGISTRY_VERSION
import hopzero
from tests.conftest import auth_headers


# ---------------------------------------------------------------------------
# 1. Manifest and Version Tests
# ---------------------------------------------------------------------------

def test_get_tool_manifest_contract(client):
    """Verifies that GET /tool-manifest adheres to the BotChain tool specification."""
    resp = client.get("/tool-manifest")
    assert resp.status_code == 200
    manifest = resp.json()

    assert manifest["id"] == "hopzero-email-forensics"
    assert manifest["name"] == "HopZero Email Forensics"
    assert manifest["version"] == hopzero.__version__
    assert manifest["category"] == "security_forensics"
    assert "email_parsing" in manifest["capabilities"]
    assert "hop0_attribution" in manifest["capabilities"]
    assert "deterministic_scoring" in manifest["capabilities"]

    op_names = [op["name"] for op in manifest["operations"]]
    assert "analyze_email" in op_names
    assert "inspect_headers" in op_names
    assert "extract_indicators" in op_names
    assert "explain_score" in op_names
    assert "get_investigation" in op_names

    # Check limits and auth
    assert manifest["limits"]["max_payload_size_bytes"] == 25 * 1024 * 1024
    assert manifest["auth"]["type"] == "bearer"


def test_get_version_endpoint(client):
    """Verifies GET /version returns complete system component versions and release hashes."""
    resp = client.get("/version")
    assert resp.status_code == 200
    v = resp.json()

    assert v["backend_version"] == hopzero.__version__
    assert v["forensics_version"] == "1.0.0"
    assert v["registry_version"] == REGISTRY_VERSION
    assert v["registry_sha256"] == "1047f1db05dd6fe51d20e124d3e42e7d7a20e985993afddfc08759942ee2a44d"
    assert v["compiler_version"] == "hopzero-compiler-v1.0.0"
    assert v["validity_engine_version"] == "vr-v1"
    assert v["score_engine_version"] == "score-engine-v2"
    assert v["conclusion_generator_version"] == "conclusion-generator-v2"
    assert v["trusted_receivers_version"] == "v1"
    assert v["shared_llm_model"] == "hermes3:3b"


def test_clean_openapi_operation_ids():
    """Verifies all OpenAPI routes have clean, predictable hopzero_* operation IDs."""
    spec = app.openapi()
    paths = spec["paths"]
    for path, methods in paths.items():
        for method, op in methods.items():
            if isinstance(op, dict) and "operationId" in op:
                op_id = op["operationId"]
                assert op_id.startswith("hopzero_"), f"Path {path} {method} has non-standard operationId: {op_id}"


# ---------------------------------------------------------------------------
# 2. Tool Operations Tests (Coarse & Fine)
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_eml_bytes():
    fixture_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "02_FORENSICS", "tests", "fixtures", "real_capture_gmail.eml"
    )
    if os.path.exists(fixture_path):
        with open(fixture_path, "rb") as f:
            return f.read()
    # Fallback minimal RFC822 EML
    return b"""From: alerts@paypal.security.com
To: user@example.com
Subject: Urgent Security Alert: Confirm Account
Date: Sat, 11 Oct 2026 12:00:00 +0000
Message-ID: <test1234@paypal.security.com>
Received: from mail.evil-relay.com (mail.evil-relay.com [198.51.100.44]) by mx.google.com with ESMTPS; Sat, 11 Oct 2026 12:00:01 +0000

Dear customer, please click https://login-paypal-verify.com to verify your wire transfer of $5,000.
"""


def test_tool_analyze_email_default_excludes_body(client, user, sample_eml_bytes):
    """
    HZ3 Requirement: Coarse analyze_email operation default include_body=false
    prevents leaking raw email body into bot context.
    """
    files = {"file": ("test_capture.eml", io.BytesIO(sample_eml_bytes), "message/rfc822")}
    headers = auth_headers(user)
    resp = client.post("/api/v1/tool/analyze-email", files=files, headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert "investigation_id" in data
    assert "run_id" in data
    assert "verdict" in data
    assert "score" in data
    assert "severity" in data
    assert "top_findings" in data
    assert "key_evidence" in data

    # Untrusted fields present
    untrusted = data.get("untrusted_fields", {})
    assert "subject" in untrusted
    # Body preview MUST be None when include_body is false
    assert untrusted.get("body_preview") is None


def test_tool_analyze_email_with_include_body(client, user, sample_eml_bytes):
    """Verifies that include_body=true includes body preview."""
    files = {"file": ("test_capture.eml", io.BytesIO(sample_eml_bytes), "message/rfc822")}
    headers = auth_headers(user)
    resp = client.post("/api/v1/tool/analyze-email?include_body=true", files=files, headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    untrusted = data.get("untrusted_fields", {})
    assert untrusted.get("body_preview") is not None


def test_tool_fine_grained_operations(client, user, sample_eml_bytes):
    """
    Verifies fine-grained operations:
    1. inspect_headers
    2. extract_indicators
    3. explain_score
    4. get_investigation summary
    """
    # First ingest and analyze
    files = {"file": ("test_capture.eml", io.BytesIO(sample_eml_bytes), "message/rfc822")}
    headers = auth_headers(user)
    ingest_resp = client.post("/api/v1/tool/analyze-email", files=files, headers=headers)
    assert ingest_resp.status_code == 200
    inv_id = ingest_resp.json()["investigation_id"]

    # 1. inspect_headers
    h_resp = client.get(f"/api/v1/tool/investigations/{inv_id}/headers", headers=headers)
    assert h_resp.status_code == 200
    h_data = h_resp.json()
    assert "routing_hops" in h_data
    assert "hop0_assessment" in h_data
    assert "authentication_results" in h_data
    assert "untrusted_fields" in h_data
    assert h_data.get("body") is None  # include_body=false by default

    # 2. extract_indicators
    ind_resp = client.get(f"/api/v1/tool/investigations/{inv_id}/indicators", headers=headers)
    assert ind_resp.status_code == 200
    ind_data = ind_resp.json()
    assert "domains" in ind_data
    assert "ips" in ind_data
    assert "urls" in ind_data
    assert "attachments" in ind_data
    assert ind_data["untrusted_markers"]["domains"] is True

    # 3. explain_score
    exp_resp = client.get(f"/api/v1/tool/investigations/{inv_id}/explain-score", headers=headers)
    assert exp_resp.status_code == 200
    exp_data = exp_resp.json()
    assert "total_score" in exp_data
    assert "severity" in exp_data
    assert "canonical_verdict" in exp_data
    assert "category_scores" in exp_data
    assert "category_caps" in exp_data
    assert "active_floors" in exp_data
    assert "findings_breakdown" in exp_data
    assert "deterministic_explanation" in exp_data
    assert isinstance(exp_data["deterministic_explanation"], str)

    # 4. get_investigation summary
    sum_resp = client.get(f"/api/v1/tool/investigations/{inv_id}/summary", headers=headers)
    assert sum_resp.status_code == 200
    sum_data = sum_resp.json()
    assert sum_data["investigation_id"] == inv_id
    assert "status" in sum_data
    assert "untrusted_fields" in sum_data
    assert "title" in sum_data["untrusted_fields"]
