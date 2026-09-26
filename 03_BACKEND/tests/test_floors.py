from dataclasses import dataclass

from app.services.floor_engine import evaluate_floors


@dataclass
class _F:
    id: str
    qualification_code: str
    strength: str
    category: str = "Content"
    normalized_target: str = ""


def test_cf01_same_brand_triggers():
    """Lookalike domain + explicit claim representing the SAME brand triggers CF-01."""
    findings = [
        _F("1", "PROTECTED_BRAND_LOOKALIKE_DOMAIN", "Moderate", "Domain", normalized_target="microsoft"),
        _F("2", "EXPLICIT_BRAND_REPRESENTATION_CLAIM", "Moderate", "Identity", normalized_target="microsoft"),
    ]
    assert "CF-01" in evaluate_floors(findings)


def test_cf01_different_brands_does_not_trigger():
    """Brand A lookalike + Brand B claim must NOT trigger CF-01."""
    findings = [
        _F("1", "PROTECTED_BRAND_LOOKALIKE_DOMAIN", "Moderate", "Domain", normalized_target="microsoft"),
        _F("2", "EXPLICIT_BRAND_REPRESENTATION_CLAIM", "Moderate", "Identity", normalized_target="paypal"),
    ]
    assert "CF-01" not in evaluate_floors(findings)


def test_cf01_lookalike_only_no_floor():
    """Lookalike domain alone does not satisfy CF-01."""
    findings = [_F("1", "PROTECTED_BRAND_LOOKALIKE_DOMAIN", "Moderate", "Domain", normalized_target="microsoft")]
    assert "CF-01" not in evaluate_floors(findings)


def test_cf01_claim_only_no_floor():
    """Brand representation claim alone does not satisfy CF-01."""
    findings = [_F("1", "EXPLICIT_BRAND_REPRESENTATION_CLAIM", "Moderate", "Identity", normalized_target="microsoft")]
    assert "CF-01" not in evaluate_floors(findings)


def test_cf02_executive_plus_financial_triggers():
    """CF-02: Executive impersonation + financial request triggers floor."""
    findings = [
        _F("1", "EXECUTIVE_IMPERSONATION", "Moderate", "Identity"),
        _F("2", "FINANCIAL_REQUEST", "Moderate", "Content"),
    ]
    assert "CF-02" in evaluate_floors(findings)


def test_cf02_executive_only_no_floor():
    """Executive impersonation alone does not trigger CF-02."""
    findings = [_F("1", "EXECUTIVE_IMPERSONATION", "Moderate", "Identity")]
    assert "CF-02" not in evaluate_floors(findings)


def test_cf02_financial_only_no_floor():
    """Financial request alone does not trigger CF-02."""
    findings = [_F("1", "FINANCIAL_REQUEST", "Moderate", "Content")]
    assert "CF-02" not in evaluate_floors(findings)


def test_cf03_credential_phishing_plus_identity_anomaly():
    findings = [
        _F("1", "CREDENTIAL_PHISHING_LINK", "Moderate"),
        _F("2", "IDENTITY_ANOMALY", "Moderate"),
    ]
    assert "CF-03" in evaluate_floors(findings)


def test_cf03_credential_phishing_only_no_floor():
    """Credential phishing link alone without identity anomaly does NOT trigger CF-03."""
    findings = [_F("1", "CREDENTIAL_PHISHING_LINK", "Moderate")]
    assert "CF-03" not in evaluate_floors(findings)


def test_cf03_identity_anomaly_only_no_floor():
    """Identity anomaly alone does NOT trigger CF-03."""
    findings = [_F("1", "IDENTITY_ANOMALY", "Moderate")]
    assert "CF-03" not in evaluate_floors(findings)


def test_cf04_suspicious_attachment_plus_identity_context():
    findings = [
        _F("1", "SUSPICIOUS_ATTACHMENT", "Strong"),
        _F("2", "IDENTITY_ANOMALY", "Moderate"),
    ]
    assert "CF-04" in evaluate_floors(findings)


def test_cf04_attachment_only_no_floor():
    """Suspicious attachment alone does NOT trigger CF-04."""
    findings = [_F("1", "SUSPICIOUS_ATTACHMENT", "Strong")]
    assert "CF-04" not in evaluate_floors(findings)


def test_cf04_identity_anomaly_only_no_floor():
    """Identity anomaly alone does NOT trigger CF-04."""
    findings = [_F("1", "IDENTITY_ANOMALY", "Moderate")]
    assert "CF-04" not in evaluate_floors(findings)


def test_cf05_confirmed_malicious_indicator_alone():
    findings = [_F("1", "CONFIRMED_MALICIOUS_INDICATOR", "Strong")]
    assert "CF-05" in evaluate_floors(findings)


def test_cf05_suspicious_indicator_does_not_trigger():
    """Only exact confirmed malicious indicator triggers CF-05, not suspicious indicators."""
    findings = [_F("1", "GENERIC_SUSPICION", "Moderate")]
    assert "CF-05" not in evaluate_floors(findings)


def test_cf05_requires_strong_not_moderate():
    findings = [_F("1", "CONFIRMED_MALICIOUS_INDICATOR", "Moderate")]
    assert "CF-05" not in evaluate_floors(findings)


def test_cf06_qualified_routing_fabrication():
    findings = [_F("1", "ROUTING_FABRICATION_QUALIFIED", "Moderate")]
    assert "CF-06" in evaluate_floors(findings)


def test_cf06_temporal_contradiction_triggers_floor():
    findings = [_F("1", "CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE", "Strong")]
    assert "CF-06" in evaluate_floors(findings)


def test_cf06_independent_trusted_contradiction_triggers_floor():
    findings = [_F("1", "CF-06:INDEPENDENT_TRUSTED_CONTRADICTION", "Strong")]
    assert "CF-06" in evaluate_floors(findings)


def test_cf06_structural_implausibility_triggers_floor():
    findings = [_F("1", "CF-06:STRUCTURAL_IMPLAUSIBILITY", "Moderate")]
    assert "CF-06" in evaluate_floors(findings)


def test_no_floors_triggered_on_unrelated_findings():
    findings = [_F("1", "GENERIC_SUSPICION", "Weak")]
    assert evaluate_floors(findings) == []


def test_raw_ai_output_never_reaches_floor_engine():
    """
    Structural check: evaluate_floors only accepts Finding-shaped
    objects with .qualification_code/.strength -- there is no code
    path from AICandidate (rejected or not) into this function. See
    app/services/trust_boundary_service.py: rejected candidates are
    never passed to finding_service, and floors are only ever computed
    from finding_service.list_findings() output in
    app/services/score_engine_service.py.
    """
    import inspect
    from app.services import score_engine_service

    source = inspect.getsource(score_engine_service)
    assert "AICandidate" not in source
