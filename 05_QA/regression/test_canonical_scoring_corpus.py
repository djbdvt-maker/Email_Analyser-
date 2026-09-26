"""
Canonical Scoring Regression Suite for HopZero (Phase 5, 6, 7, 16 locked specifications).

Verifies:
1. Pure clean baseline (0 points, LOW severity, no floors)
2. Evidence-only finding contributes exactly 0 points
3. Single Weak finding (SPF_FAIL: 6 * 0.5 = 3 raw -> 2 points, LOW)
4. Multipliers: Weak (0.5x) < Moderate (1.0x) < Strong (1.5x)
5. Category cap enforcement (Authentication capped at 16)
6. Theoretical max raw 166 -> 100 points, CRITICAL
7. Severity boundaries (29 LOW, 30 MEDIUM, 54 MEDIUM, 55 HIGH, 74 HIGH, 75 CRITICAL, 100 CRITICAL)
8. Critical Floor CF-01 (Lookalike domain + same-brand claim -> Severity HIGH, score unaffected)
9. Critical Floor CF-02 (Executive impersonation + financial request -> Severity HIGH)
10. Critical Floor CF-03 (Credential phishing link + identity anomaly -> Severity HIGH)
11. Critical Floor CF-04 (Suspicious attachment + identity anomaly -> Severity HIGH)
12. Critical Floor CF-05 (Confirmed malicious indicator -> Severity HIGH, MALICIOUS verdict)
13. Critical Floor CF-06 (Qualified routing fabrication -> Severity HIGH)
14. CF near-miss: Lookalike Brand A + Claim Brand B does NOT trigger CF-01
15. Golden Scenarios: BENIGN, SUSPICIOUS, MALICIOUS, INDETERMINATE
"""
from dataclasses import dataclass
import pytest

from app.services.score_engine import compute_score, severity_for_score
from app.services.floor_engine import evaluate_floors
from app.services.conclusion_generator import ConclusionGenerator


@dataclass
class FindingMock:
    id: str
    category: str
    strength: str
    qualification_code: str = ""
    normalized_target: str = ""
    normalized_subject_or_target: str = ""


# Case 1: Pure clean baseline
def test_case_01_pure_clean_baseline():
    findings = []
    res = compute_score(findings)
    assert res.total_score == 0
    assert res.severity == "LOW"
    assert res.triggered_floor_codes == []


# Case 2: Evidence-only finding contributes exactly 0 points
def test_case_02_evidence_only_zero_points():
    findings = [
        FindingMock("1", "Authentication", "Weak", "SPF_NONE"),
        FindingMock("2", "Authentication", "Weak", "DKIM_NONE"),
        FindingMock("3", "Social Engineering", "Weak", "GENERIC_SUSPICION"),
        FindingMock("4", "Domain", "Weak", "PUNYCODE_DOMAIN_INDICATOR"),
    ]
    res = compute_score(findings)
    assert res.total_score == 0
    assert res.severity == "LOW"
    assert res.raw_score == 0.0


# Case 3: Single Weak finding
def test_case_03_single_weak_finding():
    # SPF_FAIL base_weight = 6. Weak = 0.5x -> 3.0 raw.
    # round(3.0 / 166 * 100) = round(1.807) = 2.
    findings = [FindingMock("1", "Authentication", "Weak", "SPF_FAIL")]
    res = compute_score(findings)
    assert res.total_score == 2
    assert res.severity == "LOW"


# Case 4: Multipliers: Weak (0.5x) < Moderate (1.0x) < Strong (1.5x)
def test_case_04_strength_multipliers():
    # DMARC_FAIL base_weight = 8
    f_weak = [FindingMock("1", "Authentication", "Weak", "DMARC_FAIL")]  # 8 * 0.5 = 4 raw -> 2 pts
    f_mod = [FindingMock("1", "Authentication", "Moderate", "DMARC_FAIL")]  # 8 * 1.0 = 8 raw -> 5 pts
    f_str = [FindingMock("1", "Authentication", "Strong", "DMARC_FAIL")]  # 8 * 1.5 = 12 raw -> 7 pts

    res_w = compute_score(f_weak)
    res_m = compute_score(f_mod)
    res_s = compute_score(f_str)

    assert res_w.total_score == 2
    assert res_m.total_score == 5
    assert res_s.total_score == 7
    assert res_w.total_score < res_m.total_score < res_s.total_score


# Case 5: Category cap enforcement (Authentication cap = 16)
def test_case_05_category_cap_enforcement():
    # Authentication cap is 16:
    # DMARC_FAIL Strong (8 * 1.5 = 12) + SPF_FAIL Strong (6 * 1.5 = 9) + DKIM_FAIL Strong (6 * 1.5 = 9)
    # Sum = 30 raw, capped at 16.
    # round(16 / 166 * 100) = 10.
    findings = [
        FindingMock("1", "Authentication", "Strong", "DMARC_FAIL"),
        FindingMock("2", "Authentication", "Strong", "SPF_FAIL"),
        FindingMock("3", "Authentication", "Strong", "DKIM_FAIL"),
    ]
    res = compute_score(findings)
    assert res.category_breakdown["Authentication"] == 16.0
    assert res.total_score == 10


# Case 6: Theoretical maximum raw 166 -> 100 points, CRITICAL
def test_case_06_theoretical_max_score():
    # Findings maxing out every single one of the 9 buckets
    findings = [
        # Identity cap 20: EXECUTIVE_IMPERSONATION Strong (16*1.5=24 -> 20)
        FindingMock("1", "Identity", "Strong", "EXECUTIVE_IMPERSONATION"),
        # Authentication cap 16: DMARC_FAIL Strong (12) + SPF_FAIL Strong (9) = 21 -> 16
        FindingMock("2", "Authentication", "Strong", "DMARC_FAIL"),
        FindingMock("3", "Authentication", "Strong", "SPF_FAIL"),
        # Domain cap 16: PROTECTED_BRAND_LOOKALIKE_DOMAIN Strong (15*1.5=22.5 -> 16)
        FindingMock("4", "Domain", "Strong", "PROTECTED_BRAND_LOOKALIKE_DOMAIN"),
        # URL cap 22: CREDENTIAL_PHISHING_LINK Strong (22*1.5=33 -> 22)
        FindingMock("5", "URL", "Strong", "CREDENTIAL_PHISHING_LINK"),
        # Attachment cap 20: EXECUTABLE_IN_ARCHIVE Strong (16*1.5=24 -> 20)
        FindingMock("6", "Attachment", "Strong", "EXECUTABLE_IN_ARCHIVE"),
        # Infrastructure cap 14: BULLETPROOF_HOSTING_MATCH Strong (9*1.5=13.5) + KNOWN_BAD_ASN Weak (4) = 17.5 -> 14
        FindingMock("7", "Infrastructure", "Strong", "BULLETPROOF_HOSTING_MATCH"),
        FindingMock("8", "Infrastructure", "Weak", "KNOWN_BAD_ASN"),
        # Routing cap 20: ROUTING_FABRICATION_QUALIFIED Strong (20*1.5=30 -> 20)
        FindingMock("9", "Routing", "Strong", "ROUTING_FABRICATION_QUALIFIED"),
        # Social Engineering cap 14: FINANCIAL_REQUEST Strong (8*1.5=12) + FINANCIAL_REQUEST Weak (4) = 16 -> 14
        FindingMock("10", "Social Engineering", "Strong", "FINANCIAL_REQUEST"),
        FindingMock("11", "Social Engineering", "Weak", "FINANCIAL_REQUEST"),
        # Threat Intelligence cap 24: CONFIRMED_MALICIOUS_INDICATOR Strong (24*1.5=36 -> 24)
        FindingMock("12", "Threat Intelligence", "Strong", "CONFIRMED_MALICIOUS_INDICATOR"),
    ]
    res = compute_score(findings)
    assert res.raw_score == 166.0
    assert res.total_score == 100
    assert res.severity == "CRITICAL"


# Case 7: Severity boundaries (29 LOW, 30 MEDIUM, 54 MEDIUM, 55 HIGH, 74 HIGH, 75 CRITICAL, 100 CRITICAL)
def test_case_07_severity_boundaries():
    assert severity_for_score(0) == "LOW"
    assert severity_for_score(29) == "LOW"
    assert severity_for_score(30) == "MEDIUM"
    assert severity_for_score(54) == "MEDIUM"
    assert severity_for_score(55) == "HIGH"
    assert severity_for_score(74) == "HIGH"
    assert severity_for_score(75) == "CRITICAL"
    assert severity_for_score(100) == "CRITICAL"


# Case 8: Floor CF-01 (Lookalike domain + explicit same-brand claim) -> Severity HIGH
def test_case_08_floor_cf01():
    findings = [
        FindingMock("1", "Domain", "Moderate", "PROTECTED_BRAND_LOOKALIKE_DOMAIN", normalized_target="paypal"),
        FindingMock("2", "Identity", "Moderate", "EXPLICIT_BRAND_REPRESENTATION_CLAIM", normalized_target="paypal"),
    ]
    res = compute_score(findings)
    assert "CF-01" in res.triggered_floor_codes
    assert res.severity == "HIGH"
    # Domain (15) + Identity (15) = 30 raw -> round(30/166*100) = 18 pts
    assert res.total_score == 18  # Floor does NOT change numeric score!


# Case 9: Floor CF-02 (Executive impersonation + financial request) -> Severity HIGH
def test_case_09_floor_cf02():
    findings = [
        FindingMock("1", "Identity", "Moderate", "EXECUTIVE_IMPERSONATION"),
        FindingMock("2", "Social Engineering", "Moderate", "FINANCIAL_REQUEST"),
    ]
    res = compute_score(findings)
    assert "CF-02" in res.triggered_floor_codes
    assert res.severity == "HIGH"
    # Identity (16) + Social Engineering (8) = 24 raw -> round(24/166*100) = 14 pts
    assert res.total_score == 14


# Case 10: Floor CF-03 (Credential phishing link + identity anomaly) -> Severity HIGH
def test_case_10_floor_cf03():
    findings = [
        FindingMock("1", "URL", "Moderate", "CREDENTIAL_PHISHING_LINK"),
        FindingMock("2", "Identity", "Moderate", "IDENTITY_ANOMALY"),
    ]
    res = compute_score(findings)
    assert "CF-03" in res.triggered_floor_codes
    assert res.severity == "HIGH"
    # URL (22) + Identity (15) = 37 raw -> round(37/166*100) = 22 pts
    assert res.total_score == 22


# Case 11: Floor CF-04 (Suspicious attachment + identity anomaly) -> Severity HIGH
def test_case_11_floor_cf04():
    findings = [
        FindingMock("1", "Attachment", "Moderate", "SUSPICIOUS_ATTACHMENT"),
        FindingMock("2", "Identity", "Moderate", "IDENTITY_ANOMALY"),
    ]
    res = compute_score(findings)
    assert "CF-04" in res.triggered_floor_codes
    assert res.severity == "HIGH"
    # Attachment (14) + Identity (15) = 29 raw -> round(29/166*100) = 17 pts
    assert res.total_score == 17


# Case 12: Floor CF-05 (Confirmed malicious indicator Strong) -> Severity HIGH, MALICIOUS
def test_case_12_floor_cf05():
    findings = [
        FindingMock("1", "Threat Intelligence", "Strong", "CONFIRMED_MALICIOUS_INDICATOR"),
    ]
    res = compute_score(findings)
    assert "CF-05" in res.triggered_floor_codes
    assert res.severity == "HIGH"

    cg = ConclusionGenerator()
    out = cg.generate(score_output=res, findings=findings)
    assert out.verdict == "MALICIOUS"


# Case 13: Floor CF-06 (Qualified routing fabrication) -> Severity HIGH
def test_case_13_floor_cf06():
    findings = [
        FindingMock("1", "Routing", "Moderate", "ROUTING_FABRICATION_QUALIFIED"),
    ]
    res = compute_score(findings)
    assert "CF-06" in res.triggered_floor_codes
    assert res.severity == "HIGH"
    # Routing (20) -> round(20/166*100) = 12 pts
    assert res.total_score == 12


# Case 14: CF-01 near miss (Brand A lookalike + Brand B claim) does NOT trigger CF-01
def test_case_14_cf01_near_miss_different_brands():
    findings = [
        FindingMock("1", "Domain", "Moderate", "PROTECTED_BRAND_LOOKALIKE_DOMAIN", normalized_target="paypal"),
        FindingMock("2", "Identity", "Moderate", "EXPLICIT_BRAND_REPRESENTATION_CLAIM", normalized_target="microsoft"),
    ]
    res = compute_score(findings)
    assert "CF-01" not in res.triggered_floor_codes
    assert res.severity == "LOW"  # 18 pts -> LOW without floor


# Case 15: Golden Scenarios: BENIGN, SUSPICIOUS, MALICIOUS, INDETERMINATE
def test_case_15_golden_scenarios():
    cg = ConclusionGenerator()

    # Scenario 1: BENIGN
    res_benign = compute_score([])
    out_benign = cg.generate(score_output=res_benign, findings=[])
    assert out_benign.verdict == "BENIGN"

    # Scenario 2: SUSPICIOUS (CF-02 triggered, no CF-05)
    f_cf02 = [
        FindingMock("1", "Identity", "Moderate", "EXECUTIVE_IMPERSONATION"),
        FindingMock("2", "Social Engineering", "Moderate", "FINANCIAL_REQUEST"),
    ]
    res_cf02 = compute_score(f_cf02)
    out_suspicious = cg.generate(score_output=res_cf02, findings=f_cf02)
    assert out_suspicious.verdict == "SUSPICIOUS"

    # Scenario 3: MALICIOUS (CF-05 triggered)
    f_cf05 = [FindingMock("1", "Threat Intelligence", "Strong", "CONFIRMED_MALICIOUS_INDICATOR")]
    res_cf05 = compute_score(f_cf05)
    out_malicious = cg.generate(score_output=res_cf05, findings=f_cf05)
    assert out_malicious.verdict == "MALICIOUS"

    # Scenario 4: INDETERMINATE (missing critical evidence)
    out_indet = cg.generate(score_output=res_benign, findings=[], is_indeterminate=True)
    assert out_indet.verdict == "INDETERMINATE"
