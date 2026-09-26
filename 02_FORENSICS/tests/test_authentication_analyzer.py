import pytest
from datetime import datetime, timezone
from hopzero_forensics.interfaces import CanonicalEmail, RawHeader, EmailAddress, EmailBody, SignalState
from hopzero_forensics.analyzers.authentication import analyze_authentication

def make_email(headers):
    return CanonicalEmail(
        id="test-parse-1",
        artifact_id="artifact-1",
        message_id="<msg@test.com>",
        parsed_at=datetime.now(timezone.utc),
        headers=[RawHeader(name=h[0].lower(), value=h[1], raw_line=f"{h[0]}: {h[1]}", sequence_index=i) for i, h in enumerate(headers)],
        from_addresses=[EmailAddress(display_name="Sender", address="user@example.com", raw_value="Sender <user@example.com>", parse_state=SignalState.PRESENT)],
        reply_to_addresses=[],
        return_path=None,
        to_addresses=[],
        cc_addresses=[],
        received_chain_raw=[],
        body=EmailBody(text_plain="hello", html_sanitized="<p>hello</p>", html_available=True, links=[]),
        attachments=[],
        subject="Test",
        date_raw="Sun, 13 Sep 2026 12:00:00 +0000",
        date_parsed=datetime.now(timezone.utc),
    )

def test_spf_pass_and_dkim_pass_produces_no_candidates():
    headers = [
        ("Authentication-Results", "mx.google.com; dkim=pass header.i=@example.com; spf=pass smtp.mailfrom=example.com; dmarc=pass"),
        ("DKIM-Signature", "v=1; a=rsa-sha256; d=example.com; s=2026; ..."),
    ]
    email = make_email(headers)
    out = analyze_authentication(email)
    # Auth pass produces zero penalty candidates
    assert len(out.candidates) == 0
    assert any(f.key == "spf_result" and f.value == "pass" for f in out.facts)
    assert any(f.key == "dkim_result" and f.value == "pass" for f in out.facts)
    assert any(f.key == "dmarc_result" and f.value == "pass" for f in out.facts)

def test_spf_fail_produces_spf_fail_candidate():
    headers = [
        ("Authentication-Results", "mx.google.com; spf=fail (google.com: domain of user@example.com does not designate IP)"),
    ]
    email = make_email(headers)
    out = analyze_authentication(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "SPF_FAIL" in codes
    assert any(c.strength == "Moderate" for c in out.candidates if c.qualification_code == "SPF_FAIL")

def test_dkim_fail_produces_dkim_fail_candidate():
    headers = [
        ("Authentication-Results", "mx.google.com; dkim=fail (signature did not verify)"),
    ]
    email = make_email(headers)
    out = analyze_authentication(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "DKIM_FAIL" in codes

def test_dmarc_fail_produces_dmarc_fail_candidate():
    headers = [
        ("Authentication-Results", "mx.google.com; dmarc=fail action=none header.from=example.com"),
    ]
    email = make_email(headers)
    out = analyze_authentication(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "DMARC_FAIL" in codes

def test_missing_auth_headers_produces_none_signals():
    email = make_email([])
    out = analyze_authentication(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "SPF_NONE" in codes
    assert "DKIM_NONE" in codes
    assert "DMARC_NONE" in codes
    assert all(c.strength == "Weak" for c in out.candidates if c.qualification_code in ("SPF_NONE", "DKIM_NONE", "DMARC_NONE"))

def test_dkim_identifier_alignment_mismatch():
    headers = [
        ("Authentication-Results", "mx.google.com; dkim=pass header.i=@malicious-other.com; spf=pass"),
        ("DKIM-Signature", "v=1; d=malicious-other.com; ..."),
    ]
    email = make_email(headers)
    out = analyze_authentication(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "IDENTIFIER_ALIGNMENT_FAILURE" in codes