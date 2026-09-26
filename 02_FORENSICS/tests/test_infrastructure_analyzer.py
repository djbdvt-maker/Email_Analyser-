import pytest
from datetime import datetime, timezone
from hopzero_forensics.interfaces import CanonicalEmail, EmailBody, SignalState
from hopzero_forensics.analyzers.infrastructure import analyze_infrastructure

def make_email():
    return CanonicalEmail(
        id="test-parse-infra-1",
        artifact_id="artifact-1",
        message_id="<msg@test.com>",
        parsed_at=datetime.now(timezone.utc),
        headers=[],
        from_addresses=[],
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

def test_bulletproof_hosting_ip_detected():
    email = make_email()
    out = analyze_infrastructure(email, probable_origin_ip="192.0.2.100")
    codes = [c.qualification_code for c in out.candidates]
    assert "BULLETPROOF_HOSTING_MATCH" in codes
    c = next(c for c in out.candidates if c.qualification_code == "BULLETPROOF_HOSTING_MATCH")
    assert c.strength == "Moderate"

def test_clean_ip_produces_no_candidates():
    email = make_email()
    out = analyze_infrastructure(email, probable_origin_ip="8.8.8.8")
    assert len(out.candidates) == 0

def test_missing_ip_returns_unavailable():
    email = make_email()
    out = analyze_infrastructure(email, probable_origin_ip=None)
    assert len(out.candidates) == 0
    assert any(f.key == "origin_ip" and f.state == SignalState.UNAVAILABLE for f in out.facts)