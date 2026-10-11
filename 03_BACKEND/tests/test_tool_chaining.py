"""
Tests for BotChain Tool Chaining (HZ6).
=======================================
Demonstrates multi-tool orchestration between:
1. Tool 1: HopZero Email Forensics (`hopzero-email-forensics`)
2. Tool 2: HopZero Domain & Lookalike Checker (`hopzero-domain-checker`)

Workflow:
- Orchestrator bot calls Tool 1 to analyze an untrusted email.
- Tool 1 extracts indicators (domains, IPs, links) and scores the message.
- Orchestrator bot extracts observed domains and pipes them into Tool 2.
- Tool 2 performs deep lookalike / homoglyph analysis on the indicators.
- Both tools produce corroborating, deterministic evidence.
"""
import io
import pytest
from fastapi.testclient import TestClient

CHAIN_SAMPLE_EML = b"""From: "PayPal Account Security" <service@paypal-security-alert.com>
To: target-user@victim-corp.com
Subject: Account Suspension Notice: Immediate Action Required
Date: Sat, 11 Oct 2026 15:00:00 +0000
Message-ID: <chain-test-001@paypal-security-alert.com>
Received: from mail.paypal-security-alert.com (mail.paypal-security-alert.com [198.51.100.77])
        by mx.google.com with ESMTPS id chain123;
        Sat, 11 Oct 2026 15:00:01 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Your PayPal account has been temporarily restricted due to unauthorized login activity.
Visit http://paypal-security-alert.com/restore to reactivate your account immediately.
"""


def test_botchain_two_tool_chaining(client: TestClient):
    """
    Demonstrates orchestrating Tool 1 (Email Forensics) and Tool 2 (Domain Tool)
    in a BotChain workflow.
    """
    # -----------------------------------------------------------------------
    # Step 1: Call Tool 1 (HopZero Email Forensics) to analyze the email
    # -----------------------------------------------------------------------
    tool1_files = {
        "file": ("suspicious_email.eml", io.BytesIO(CHAIN_SAMPLE_EML), "message/rfc822")
    }
    tool1_res = client.post("/api/v1/tool/analyze-email", files=tool1_files)
    assert tool1_res.status_code == 200
    t1_data = tool1_res.json()

    assert t1_data["verdict"] in ("SUSPICIOUS", "MALICIOUS")
    assert "investigation_id" in t1_data
    inv_id = t1_data["investigation_id"]

    # -----------------------------------------------------------------------
    # Step 2: Query Tool 1 fine endpoint to extract indicators
    # -----------------------------------------------------------------------
    ind_res = client.get(f"/api/v1/tool/investigations/{inv_id}/indicators")
    assert ind_res.status_code == 200
    ind_data = ind_res.json()

    observed_domains = ind_data["domains"]
    assert len(observed_domains) > 0
    assert "paypal-security-alert.com" in observed_domains

    # -----------------------------------------------------------------------
    # Step 3: Orchestrator pipes extracted domains into Tool 2 (Domain Tool)
    # -----------------------------------------------------------------------
    tool2_res = client.post("/api/v1/domain/check-batch", json={"domains": observed_domains})
    assert tool2_res.status_code == 200
    t2_data = tool2_res.json()

    assert t2_data["total_evaluated"] == len(observed_domains)
    results = t2_data["results"]

    # Verify lookalike was caught by Tool 2
    lookalike_found = False
    for r in results:
        if r["normalized_domain"] == "paypal-security-alert.com":
            assert r["is_lookalike"] is True
            assert r["matched_brand"] == "PayPal"
            assert r["risk_verdict"] == "HIGH"
            lookalike_found = True

    assert lookalike_found, "Tool 2 should independently confirm lookalike brand spoofing"
