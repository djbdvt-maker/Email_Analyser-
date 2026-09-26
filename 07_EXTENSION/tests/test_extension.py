import json
import os
import pytest

EXT_DIR = os.path.join(os.path.dirname(__file__), "..")

def read_file(*parts):
    with open(os.path.join(EXT_DIR, *parts), "r", encoding="utf-8") as f:
        return f.read()

def test_manifest_validity():
    manifest = json.loads(read_file("manifest.json"))
    assert manifest["manifest_version"] == 3

def test_gmail_adapter_exists():
    assert "gmail_adapter.js" in read_file("manifest.json")
    content = read_file("src", "content", "gmail_adapter.js")
    assert "capture_mode" in content

def test_backend_api_client_exists():
    content = read_file("src", "api", "hopzero_client.js")
    assert "class HopZeroClient" in content

def test_get_analysis_run_uses_exact_endpoint():
    content = read_file("src", "api", "hopzero_client.js")
    assert "investigations/${investigationId}/analysis-runs/${runId}" in content

def test_get_findings_accepts_analysis_run_id():
    content = read_file("src", "api", "hopzero_client.js")
    assert "?analysis_run_id=${runId}" in content

def test_get_score_uses_total_score():
    content = read_file("src", "popup", "popup.js")
    assert "scoreData.total_score" in content

def test_conclusion_text_displayed():
    content = read_file("src", "popup", "popup.js")
    assert "scoreData.conclusion_text" in content

def test_verdict_displayed():
    content = read_file("src", "popup", "popup.js")
    assert "scoreData.verdict" in content

def test_no_fallback_to_completed():
    content = read_file("src", "popup", "popup.js")
    assert "status || \"COMPLETED\"" not in content

def test_no_date_now_provider_message_id_fallback():
    content = read_file("src", "content", "gmail_adapter.js")
    assert "Date.now()" not in content

def test_feedback_creates_new_run():
    content = read_file("src", "popup", "popup.js")
    assert "client.submitFeedback" in content
    assert "fb.new_analysis_run_id" in content

def test_new_run_polled():
    content = read_file("src", "popup", "popup.js")
    assert "pollRun(newRunId, true)" in content

def test_compare_runs_called():
    content = read_file("src", "popup", "popup.js")
    assert "client.compareRuns(" in content

def test_enforcement_request_exists():
    content = read_file("src", "api", "hopzero_client.js")
    assert "/enforcement/request" in content

def test_explicit_authorization_exists():
    content = read_file("src", "api", "hopzero_client.js")
    assert "/authorize" in content

def test_execution_occurs_only_after_authorization():
    content = read_file("src", "popup", "popup.js")
    # request -> authorize -> execute chain
    assert "await client.authorizeEnforcement" in content
    assert "await client.executeEnforcement" in content

def test_no_firewall_commands_exist():
    content = read_file("src", "api", "hopzero_client.js") + read_file("src", "popup", "popup.js")
    assert "iptables" not in content
    assert "ufw" not in content

def test_no_score_calculation_exists():
    content = read_file("src", "popup", "popup.js")
    assert "scoreData.score +" not in content

def test_no_cf_logic_exists():
    content = read_file("src", "popup", "popup.js")
    assert "CF-01" not in content

def test_no_attacker_ip_inference_exists():
    content = read_file("src", "popup", "popup.js")
    assert "inferAttackerIp" not in content

def test_email_content_rendered_safely():
    content = read_file("src", "popup", "popup.js")
    assert "dangerouslySetInnerHTML" not in content
    assert "innerText" in content

def test_no_hardcoded_secrets_exist():
    content = read_file("src", "api", "hopzero_client.js") + read_file("src", "popup", "popup.js")
    assert "sk-" not in content

def test_no_raw_email_claim_made_when_dom_reconstructed():
    content = read_file("src", "content", "gmail_adapter.js")
    assert "raw_available: false" in content
