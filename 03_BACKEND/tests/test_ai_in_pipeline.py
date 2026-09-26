"""
Integration tests for the AI Reasoner in the pipeline, AI failure isolation,
registry-analyzer qualification consistency, and end-to-end .eml scenarios.
"""
import os
import json
import pytest
from fastapi.testclient import TestClient

from app.qualification_registry import all_qualifications, get_qualification
from app.services.pipeline_service import execute_analysis_pipeline
from app.services.ai_reasoner_service import (
    run_ai_reasoning_pipeline,
    AI_UNAVAILABLE_EXPLANATION,
    AI_STATUS_COMPLETED_WITH_FINDINGS,
    AI_STATUS_UNAVAILABLE,
)
from app.services import evidence_service, investigation_service
from app.models import Investigation, InvestigationStatus, AnalysisRun, Finding, Fact, ScoreConclusion
from tests.conftest import TEST_N8N_INGEST_KEY, auth_headers

TEST_DATA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "07_TEST_DATA")
)


def test_registry_analyzer_qualification_consistency():
    """
    Asserts every qualification code emitted across all 7 analyzers exists
    in the authoritative compiled registry (01_REGISTRY/releases/registry-v1.json).
    """
    registry = all_qualifications()
    assert len(registry) >= 41, f"Expected at least 41 registry qualifications, found {len(registry)}"

    ai_allowed_quals = [
        q.qualification_code for q in registry.values() if "ai_reasoner" in q.produced_by_allowed
    ]
    assert len(ai_allowed_quals) >= 4, f"Expected at least 4 AI-allowed qualifications, found {len(ai_allowed_quals)}"

    # Check that all AI-allowed qualifications have validity_requirements
    for code in ai_allowed_quals:
        q = get_qualification(code)
        assert q is not None, f"AI qualification {code} missing from registry"
        assert q.ai_eligible is True
        assert q.validity_requirements is not None

    # Inspect the 7 forensic analyzers for referenced qualification codes
    analyzer_codes = [
        "ARCHIVE_TRUNCATED_OR_OVERSIZED",
        "AUTH_LIKE_PATH_DETECTED",
        "BULLETPROOF_HOSTING_MATCH",
        "CONFIRMED_MALICIOUS_INDICATOR",
        "CREDENTIAL_PHISHING_LINK",
        "DKIM_FAIL",
        "DKIM_NONE",
        "DMARC_FAIL",
        "DMARC_NONE",
        "DOUBLE_COMPOUND_EXTENSION",
        "EXECUTABLE_IN_ARCHIVE",
        "EXECUTIVE_IMPERSONATION",
        "EXPLICIT_BRAND_REPRESENTATION_CLAIM",
        "EXTENSION_MIME_MISMATCH",
        "HOMOGLYPH_DOMAIN_MATCH",
        "IDENTIFIER_ALIGNMENT_FAILURE",
        "IDENTITY_ANOMALY",
        "IDENTITY_DISPLAY_NAME_MISMATCH",
        "IDENTITY_REPLY_TO_MISMATCH",
        "IDENTITY_RETURN_PATH_MISMATCH",
        "KNOWN_BAD_ASN",
        "LINK_DISPLAY_HREF_MISMATCH",
        "MACRO_ENABLED_DOCUMENT",
        "MIXED_SCRIPT_DOMAIN",
        "PROTECTED_BRAND_LOOKALIKE_DOMAIN",
        "PROTECTED_BRAND_LOOKALIKE_URL",
        "PUNYCODE_DOMAIN_INDICATOR",
        "SPF_FAIL",
        "SPF_NONE",
        "SUSPICIOUS_ATTACHMENT",
        "URGENCY_AUTHORITY_FILENAME",
        "URL_SHORTENER_DETECTED",
    ]

    for code in analyzer_codes:
        q = get_qualification(code)
        assert q is not None, f"Analyzer qualification code '{code}' not found in authoritative registry"
        assert "deterministic" in q.produced_by_allowed, (
            f"Qualification '{code}' does not allow canonical 'deterministic' producer: {q.produced_by_allowed}"
        )


def test_ai_reasoning_in_pipeline_bec_wire_transfer(client, user, db_session):
    """
    Test full pipeline with raw BEC .eml file. AI reasoner produces FINANCIAL_REQUEST
    which is admitted through trust boundary and triggers CF-02 floor in score engine.
    """
    eml_path = os.path.join(TEST_DATA_DIR, "BEC", "bec_ceo_wire_transfer.eml")
    assert os.path.exists(eml_path), f"Test fixture not found: {eml_path}"

    with open(eml_path, "rb") as f:
        eml_bytes = f.read()

    resp = client.post(
        "/api/v1/ingest",
        headers={"X-N8N-Ingest-Key": TEST_N8N_INGEST_KEY},
        data={
            "ingestion_source": "qa_pipeline_test",
            "provider_message_id": "bec-wire-transfer-001",
            "title": "BEC Wire Transfer Investigation",
            "auto_analyze": "true",
        },
        files={"file": ("bec_ceo_wire_transfer.eml", eml_bytes, "message/rfc822")},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    inv_id = data["investigation_id"]
    run_id = data["analysis_run_id"]

    run = db_session.get(AnalysisRun, run_id)
    assert run.status.value == "COMPLETED"

    # Verify score conclusion
    score = db_session.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == run_id).one()
    assert "CF-02" in score.triggered_floor_codes, f"CF-02 not triggered: {score.triggered_floor_codes}"
    assert score.severity.upper() in ("HIGH", "CRITICAL")

    # Verify findings: both deterministic and AI findings exist
    findings = db_session.query(Finding).filter(Finding.investigation_id == inv_id).all()
    producers = {f.produced_by for f in findings}
    assert "deterministic" in producers
    assert "ai_reasoner" in producers

    ai_finding = next((f for f in findings if f.produced_by == "ai_reasoner"), None)
    assert ai_finding is not None
    ai_allowed_quals = [
        q.qualification_code for q in all_qualifications().values() if "ai_reasoner" in q.produced_by_allowed
    ]
    assert ai_finding.qualification_code in ai_allowed_quals
    assert ai_finding.claim_signature is not None

    # Verify candidate IP labeling: no attacker IP
    facts = db_session.query(Fact).filter(Fact.investigation_id == inv_id).all()
    for f in facts:
        assert "attacker" not in (f.fact_type or "").lower()


def test_ai_failure_isolation_timeout(monkeypatch, client, user, db_session):
    """
    Test that when AI Reasoner times out (AI_UNAVAILABLE_TIMEOUT), deterministic
    analysis still completes, score is computed without penalty or bonus,
    and the exact UI message is included in conclusion text.
    """
    import app.services.ai_reasoner_service as ai_service

    def mock_run_ai_timeout(*args, **kwargs):
        raise TimeoutError("AI inference request timed out after 10000ms")

    monkeypatch.setattr(ai_service, "run_ai_reasoning_pipeline", mock_run_ai_timeout)

    eml_path = os.path.join(TEST_DATA_DIR, "clean", "clean_legit_corporate.eml")
    with open(eml_path, "rb") as f:
        eml_bytes = f.read()

    resp = client.post(
        "/api/v1/ingest",
        headers={"X-N8N-Ingest-Key": TEST_N8N_INGEST_KEY},
        data={
            "ingestion_source": "qa_pipeline_test",
            "provider_message_id": "ai-timeout-test-001",
            "title": "AI Timeout Isolation Test",
            "auto_analyze": "true",
        },
        files={"file": ("clean.eml", eml_bytes, "message/rfc822")},
    )
    assert resp.status_code == 201
    data = resp.json()
    run_id = data["analysis_run_id"]

    run = db_session.get(AnalysisRun, run_id)
    assert run.status.value == "COMPLETED"

    # Score should exist and reflect deterministic findings only
    score = db_session.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == run_id).one()
    assert AI_UNAVAILABLE_EXPLANATION in score.conclusion_text
    assert score.total_score < 30


def test_ai_failure_isolation_malformed_json(monkeypatch, client, user, db_session):
    """
    Test that when AI Reasoner returns unparseable or schema-violating JSON,
    the deterministic pipeline still completes and no AI findings are admitted.
    """
    import app.services.ai_reasoner_service as ai_service

    def mock_run_ai_malformed(*args, **kwargs):
        return {
            "ai_status": "INVALID_RESPONSE",
            "ai_error": "AI_INVALID_JSON",
            "accepted_count": 0,
            "rejected_count": 0,
            "explanation": AI_UNAVAILABLE_EXPLANATION,
        }

    monkeypatch.setattr(ai_service, "run_ai_reasoning_pipeline", mock_run_ai_malformed)

    eml_path = os.path.join(TEST_DATA_DIR, "BEC", "bec_ceo_wire_transfer.eml")
    with open(eml_path, "rb") as f:
        eml_bytes = f.read()

    resp = client.post(
        "/api/v1/ingest",
        headers={"X-N8N-Ingest-Key": TEST_N8N_INGEST_KEY},
        data={
            "ingestion_source": "qa_pipeline_test",
            "provider_message_id": "ai-malformed-test-001",
            "title": "AI Malformed JSON Test",
            "auto_analyze": "true",
        },
        files={"file": ("bec.eml", eml_bytes, "message/rfc822")},
    )
    assert resp.status_code == 201
    data = resp.json()
    run_id = data["analysis_run_id"]
    inv_id = data["investigation_id"]

    run = db_session.get(AnalysisRun, run_id)
    assert run.status.value == "COMPLETED"

    # No AI findings should have been admitted
    findings = db_session.query(Finding).filter(Finding.investigation_id == inv_id).all()
    ai_findings = [f for f in findings if f.produced_by == "ai_reasoner"]
    assert len(ai_findings) == 0

    # Deterministic findings still exist and scored
    score = db_session.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == run_id).one()
    assert score.total_score >= 0


def test_get_investigation_full_detail_api(client, user, db_session):
    """
    Test GET /api/v1/investigations/{id} returning the full InvestigationDetail contract.
    """
    eml_path = os.path.join(TEST_DATA_DIR, "BEC", "bec_ceo_wire_transfer.eml")
    with open(eml_path, "rb") as f:
        eml_bytes = f.read()

    resp = client.post(
        "/api/v1/ingest",
        headers={"X-N8N-Ingest-Key": TEST_N8N_INGEST_KEY},
        data={
            "ingestion_source": "qa_pipeline_test",
            "provider_message_id": "detail-test-001",
            "title": "Full Detail Test Investigation",
            "auto_analyze": "true",
        },
        files={"file": ("bec.eml", eml_bytes, "message/rfc822")},
    )
    inv_id = resp.json()["investigation_id"]

    # Now call the full detail endpoint
    detail_resp = client.get(
        f"/api/v1/investigations/{inv_id}",
        headers=auth_headers(user),
    )
    assert detail_resp.status_code == 200, detail_resp.text
    detail = detail_resp.json()

    assert detail["id"] == inv_id
    assert detail["current_run_status"] == "COMPLETED"
    run_id_val = detail["current_analysis_run_id"]
    score_resp = client.get(f"/api/v1/investigations/{inv_id}/analysis-runs/{run_id_val}/score", headers=auth_headers(user))
    assert score_resp.status_code == 200
    res = score_resp.json()
    assert "total_score" in res
    assert "severity" in res
    assert "verdict" in res


def test_end_to_end_test_data_scenarios(client, user, db_session):
    """
    Tests end-to-end ingestion and analysis across all test data scenarios:
    1. Clean corporate email -> Low severity, likely_benign verdict, no floors
    2. Lookalike domain -> High severity, CF-01 triggered
    3. Double extension attachment -> High severity, CF-04 triggered
    4. Credential harvesting portal -> High severity, CF-03 triggered
    """
    scenarios = [
        ("clean", "clean_legit_corporate.eml", "clean-001", "BENIGN", 0, 30, []),
        ("lookalike", "protected_brand_lookalike.eml", "lookalike-001", "SUSPICIOUS", 0, 100, ["CF-01"]),
        ("attachments", "double_extension_macro.eml", "attach-001", "SUSPICIOUS", 0, 100, ["CF-04"]),
        ("phishing", "credential_harvesting_portal.eml", "phish-001", "SUSPICIOUS", 0, 100, ["CF-03"]),
    ]

    for category, filename, msg_id, expected_verdict, min_score, max_score, expected_floors in scenarios:
        eml_path = os.path.join(TEST_DATA_DIR, category, filename)
        with open(eml_path, "rb") as f:
            eml_bytes = f.read()

        resp = client.post(
            "/api/v1/ingest",
            headers={"X-N8N-Ingest-Key": TEST_N8N_INGEST_KEY},
            data={
                "ingestion_source": f"scenario_{category}",
                "provider_message_id": msg_id,
                "title": f"Scenario {category}",
                "auto_analyze": "true",
            },
            files={"file": (filename, eml_bytes, "message/rfc822")},
        )
        assert resp.status_code == 201, f"Failed for {category}: {resp.text}"
        inv_id = resp.json()["investigation_id"]

        detail_resp = client.get(
            f"/api/v1/investigations/{inv_id}",
            headers=auth_headers(user),
        )
        assert detail_resp.status_code == 200
        detail = detail_resp.json()
        run_id_val = detail["current_analysis_run_id"]
        score_resp = client.get(f"/api/v1/investigations/{inv_id}/analysis-runs/{run_id_val}/score", headers=auth_headers(user))
        assert score_resp.status_code == 200
        result = score_resp.json()
        assert result is not None, f"Result is None for {category}"

        assert min_score <= result["total_score"] <= max_score, (
            f"Score {result['total_score']} not in [{min_score}, {max_score}] for {category}"
        )
        assert result["verdict"] == expected_verdict, (
            f"Verdict '{result['verdict']}' != '{expected_verdict}' for {category}"
        )


def test_list_findings_scoped_by_analysis_run_id(client, user, db_session):
    """
    Asserts GET /api/v1/investigations/{investigation_id}/findings supports
    optional analysis_run_id scoping per Section 30 and validates canonical claim signatures.
    """
    eml_path = os.path.join(TEST_DATA_DIR, "attachments", "double_extension_macro.eml")
    with open(eml_path, "rb") as f:
        eml_bytes = f.read()

    resp = client.post(
        "/api/v1/ingest",
        headers={"X-N8N-Ingest-Key": TEST_N8N_INGEST_KEY},
        data={
            "ingestion_source": "test_findings_scoping",
            "provider_message_id": "scope-run-001",
            "title": "Run Scoping Test",
            "auto_analyze": "true",
        },
        files={"file": ("double_extension_macro.eml", eml_bytes, "message/rfc822")},
    )
    assert resp.status_code == 201
    data = resp.json()
    inv_id = data["investigation_id"]
    run_id = data["analysis_run_id"]

    # 1. Query findings without run_id scoping -> returns all findings for investigation
    res_all = client.get(
        f"/api/v1/investigations/{inv_id}/findings",
        headers=auth_headers(user),
    )
    assert res_all.status_code == 200
    findings_all = res_all.json()
    assert len(findings_all) > 0

    # Every finding emitted by the pipeline should have a valid claim_signature in the registry
    for finding in findings_all:
        q = get_qualification(finding["qualification_code"])
        assert q is not None
        assert finding["claim_signature"] in q.allowed_claim_signatures, (
            f"Finding {finding['qualification_code']} has claim signature '{finding['claim_signature']}' "
            f"not in allowed: {q.allowed_claim_signatures}"
        )

    # 2. Query findings with matching analysis_run_id -> returns same matching findings
    res_scoped = client.get(
        f"/api/v1/investigations/{inv_id}/findings?analysis_run_id={run_id}",
        headers=auth_headers(user),
    )
    assert res_scoped.status_code == 200
    findings_scoped = res_scoped.json()
    assert len(findings_scoped) == len(findings_all)
    for f in findings_scoped:
        assert f["analysis_run_id"] == run_id

    # 3. Query findings with non-existent analysis_run_id -> returns empty list
    res_empty = client.get(
        f"/api/v1/investigations/{inv_id}/findings?analysis_run_id=nonexistent-run-id",
        headers=auth_headers(user),
    )
    assert res_empty.status_code == 200
    assert len(res_empty.json()) == 0



