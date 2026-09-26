import pytest
from datetime import datetime, timezone
from hopzero_forensics.interfaces import CanonicalEmail, EmailAddress, EmailBody, SignalState
from hopzero_forensics.analyzers.identity import analyze_identity

def make_email(from_addr, reply_to=None, return_path=None):
    return CanonicalEmail(
        id="test-parse-id-1",
        artifact_id="artifact-1",
        message_id="<msg@test.com>",
        parsed_at=datetime.now(timezone.utc),
        headers=[],
        from_addresses=[from_addr],
        reply_to_addresses=[reply_to] if reply_to else [],
        return_path=return_path,
        to_addresses=[],
        cc_addresses=[],
        received_chain_raw=[],
        body=EmailBody(text_plain="body", html_sanitized="<p>body</p>", html_available=True, links=[]),
        attachments=[],
        subject="Subject",
        date_raw="",
        date_parsed=datetime.now(timezone.utc),
    )

def test_exact_matching_identity_produces_no_candidates():
    from_addr = EmailAddress("Alice Smith", "alice@acme.com", "Alice <alice@acme.com>", SignalState.PRESENT)
    reply_to = EmailAddress("Alice Smith", "alice@acme.com", "Alice <alice@acme.com>", SignalState.PRESENT)
    return_path = EmailAddress(None, "alice@acme.com", "alice@acme.com", SignalState.PRESENT)
    email = make_email(from_addr, reply_to, return_path)
    out = analyze_identity(email)
    assert len(out.candidates) == 0

def test_reply_to_mismatch_detected():
    from_addr = EmailAddress("Alice Smith", "alice@acmecorp.com", "Alice <alice@acmecorp.com>", SignalState.PRESENT)
    reply_to = EmailAddress("Alice", "alice.external@gmail.com", "Alice <alice.external@gmail.com>", SignalState.PRESENT)
    email = make_email(from_addr, reply_to)
    out = analyze_identity(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "IDENTITY_REPLY_TO_MISMATCH" in codes
    c = next(c for c in out.candidates if c.qualification_code == "IDENTITY_REPLY_TO_MISMATCH")
    assert c.strength == "Moderate"

def test_return_path_mismatch_detected():
    from_addr = EmailAddress("Support", "support@acmecorp.com", "Support <support@acmecorp.com>", SignalState.PRESENT)
    return_path = EmailAddress(None, "bounce@suspicious-relay.net", "bounce@suspicious-relay.net", SignalState.PRESENT)
    email = make_email(from_addr, return_path=return_path)
    out = analyze_identity(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "IDENTITY_RETURN_PATH_MISMATCH" in codes
    c = next(c for c in out.candidates if c.qualification_code == "IDENTITY_RETURN_PATH_MISMATCH")
    assert c.strength == "Moderate"

def test_executive_impersonation_claim_detected():
    from_addr = EmailAddress("Ken Whitfield, CEO", "k.whitfield@phishing-lookalike.com", "Ken Whitfield, CEO <k.whitfield@phishing-lookalike.com>", SignalState.PRESENT)
    email = make_email(from_addr)
    out = analyze_identity(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "EXECUTIVE_IMPERSONATION" in codes
    assert "IDENTITY_ANOMALY" in codes
    c = next(c for c in out.candidates if c.qualification_code == "EXECUTIVE_IMPERSONATION")
    assert c.strength == "Strong"