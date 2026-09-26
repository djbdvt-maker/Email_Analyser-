import pytest
from datetime import datetime, timezone
from hopzero_forensics.interfaces import CanonicalEmail, EmailAddress, EmailBody, SignalState
from hopzero_forensics.analyzers.domain import analyze_domain

def make_email(from_domain):
    from_addr = EmailAddress("User", f"user@{from_domain}", f"User <user@{from_domain}>", SignalState.PRESENT)
    return CanonicalEmail(
        id="test-parse-dom-1",
        artifact_id="artifact-1",
        message_id="<msg@test.com>",
        parsed_at=datetime.now(timezone.utc),
        headers=[],
        from_addresses=[from_addr],
        reply_to_addresses=[],
        return_path=None,
        to_addresses=[],
        cc_addresses=[],
        received_chain_raw=[],
        body=EmailBody(text_plain="body", html_sanitized="<p>body</p>", html_available=True, links=[]),
        attachments=[],
        subject="Test",
        date_raw="",
        date_parsed=datetime.now(timezone.utc),
    )

def test_normal_ascii_domain_produces_no_candidates():
    email = make_email("example.com")
    out = analyze_domain(email)
    assert len(out.candidates) == 0

def test_punycode_domain_detected():
    email = make_email("xn--pypal-4ve.com")
    out = analyze_domain(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "PUNYCODE_DOMAIN_INDICATOR" in codes

def test_protected_brand_lookalike_domain_detected():
    email = make_email("acme-security-update.com")
    out = analyze_domain(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "PROTECTED_BRAND_LOOKALIKE_DOMAIN" in codes
    c = next(c for c in out.candidates if c.qualification_code == "PROTECTED_BRAND_LOOKALIKE_DOMAIN")
    assert c.strength == "Moderate"

def test_exact_protected_brand_is_not_flagged():
    email = make_email("google.com")
    out = analyze_domain(email)
    assert len(out.candidates) == 0