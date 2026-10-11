"""
Tests for HopZero Domain & Lookalike Checker Tool (HZ6).
========================================================
Verifies:
1. Manifest and version endpoint contract compliance.
2. Homoglyph, punycode, and brand lookalike detection accuracy.
3. Deterministic risk verdict computation (CRITICAL, HIGH, MEDIUM, LOW).
4. Batch domain evaluation.
5. Zero LLM scoring authority.
"""
import pytest
from fastapi.testclient import TestClient

from hopzero.tools.domain import DOMAIN_TOOL_MANIFEST


def test_domain_tool_manifest_contract(client: TestClient):
    """Verifies that the Domain Tool manifest adheres to TOOL_SUITE_STANDARD.md."""
    res = client.get("/api/v1/domain/manifest")
    assert res.status_code == 200
    m = res.json()

    assert m["id"] == "hopzero-domain-checker"
    assert m["name"] == "HopZero Domain & Lookalike Checker"
    assert "punycode_detection" in m["capabilities"]
    assert "brand_lookalike_detection" in m["capabilities"]

    op_names = [op["name"] for op in m["operations"]]
    assert "check_domain" in op_names
    assert "check_domains_batch" in op_names


def test_domain_tool_version_endpoint(client: TestClient):
    """Verifies the Domain Tool version endpoint."""
    res = client.get("/api/v1/domain/version")
    assert res.status_code == 200
    v = res.json()
    assert v["tool_id"] == "hopzero-domain-checker"
    assert v["tool_version"] == "1.0.0"
    assert "protected_brands_version" in v


def test_legitimate_brand_domain_evaluation(client: TestClient):
    """Verifies that legitimate brand domains are marked clean / LOW risk."""
    legit_domains = ["microsoft.com", "paypal.com", "apple.com", "google.com"]
    for d in legit_domains:
        res = client.post("/api/v1/domain/check", json={"domain": d})
        assert res.status_code == 200
        data = res.json()
        assert data["is_lookalike"] is False
        assert data["is_homoglyph"] is False
        assert data["risk_verdict"] == "LOW"
        assert len(data["findings"]) == 0


def test_brand_lookalike_detection(client: TestClient):
    """Verifies detection of typosquatting / prefix-suffix lookalikes."""
    lookalikes = [
        ("paypal-security-center.com", "PayPal"),
        ("login-microsoft-verify.com", "Microsoft"),
        ("appleid-support-account.com", "Apple"),
    ]
    for domain, expected_brand in lookalikes:
        res = client.post("/api/v1/domain/check", json={"domain": domain})
        assert res.status_code == 200
        data = res.json()
        assert data["is_lookalike"] is True
        assert data["matched_brand"] == expected_brand
        assert data["risk_verdict"] == "HIGH"
        finding_codes = [f["qualification_code"] for f in data["findings"]]
        assert "LOOKALIKE_BRAND_DOMAIN" in finding_codes


def test_homoglyph_confusable_detection(client: TestClient):
    """Verifies detection of Cyrillic/Greek homoglyphs spoofing protected brands."""
    # Cyrillic 'а' (\u0430) spoofing 'paypal.com'
    cyrillic_paypal = "p\u0430ypal.com"
    res = client.post("/api/v1/domain/check", json={"domain": cyrillic_paypal})
    assert res.status_code == 200
    data = res.json()
    assert data["is_homoglyph"] is True
    assert data["matched_brand"] == "PayPal"
    assert data["risk_verdict"] == "CRITICAL"
    finding_codes = [f["qualification_code"] for f in data["findings"]]
    assert "HOMOGLYPH_DOMAIN" in finding_codes


def test_punycode_detection(client: TestClient):
    """Verifies detection of generic punycode domain names."""
    punycode_domain = "xn--e1afmkfd.com"
    res = client.post("/api/v1/domain/check", json={"domain": punycode_domain})
    assert res.status_code == 200
    data = res.json()
    assert data["is_punycode"] is True
    assert data["risk_verdict"] == "MEDIUM"


def test_batch_domain_evaluation(client: TestClient):
    """Verifies batch checking of multiple domains."""
    domains = [
        "microsoft.com",
        "paypal-security-alert.com",
        "example-clean-site.org",
    ]
    res = client.post("/api/v1/domain/check-batch", json={"domains": domains})
    assert res.status_code == 200
    batch = res.json()
    assert batch["total_evaluated"] == 3
    results = batch["results"]
    assert results[0]["risk_verdict"] == "LOW"
    assert results[1]["is_lookalike"] is True
    assert results[1]["risk_verdict"] == "HIGH"
    assert results[2]["risk_verdict"] == "LOW"
