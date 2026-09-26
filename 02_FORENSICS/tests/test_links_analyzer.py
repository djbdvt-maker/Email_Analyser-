import pytest
from datetime import datetime, timezone
from hopzero_forensics.interfaces import CanonicalEmail, EmailBody, ExtractedLink, SignalState
from hopzero_forensics.analyzers.links import analyze_links

def make_email_with_links(links):
    return CanonicalEmail(
        id="test-parse-links-1",
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
        body=EmailBody(text_plain="body", html_sanitized="<p>body</p>", html_available=True, links=links),
        attachments=[],
        subject="Test",
        date_raw="",
        date_parsed=datetime.now(timezone.utc),
    )

def test_benign_link_produces_no_candidates():
    links = [ExtractedLink("l1", "https://example.com/about", "About Us", "html", None)]
    email = make_email_with_links(links)
    out = analyze_links(email)
    assert len(out.candidates) == 0

def test_display_href_mismatch_detected():
    links = [ExtractedLink("l1", "https://evil-site.com/steal", "https://google.com/login", "html", None)]
    email = make_email_with_links(links)
    out = analyze_links(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "LINK_DISPLAY_HREF_MISMATCH" in codes
    c = next(c for c in out.candidates if c.qualification_code == "LINK_DISPLAY_HREF_MISMATCH")
    assert c.strength == "Weak"

def test_url_shortener_detected():
    links = [ExtractedLink("l1", "https://bit.ly/3xYz78", "Click Here", "html", None)]
    email = make_email_with_links(links)
    out = analyze_links(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "URL_SHORTENER_DETECTED" in codes
    c = next(c for c in out.candidates if c.qualification_code == "URL_SHORTENER_DETECTED")
    assert c.strength == "Weak"

def test_auth_like_path_detected():
    links = [ExtractedLink("l1", "https://random-hosting-123.com/login", "Log In to Account", "html", None)]
    email = make_email_with_links(links)
    out = analyze_links(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "AUTH_LIKE_PATH_DETECTED" in codes
    assert "CREDENTIAL_PHISHING_LINK" not in codes

def test_credential_phishing_link_detected_with_deceptive_anchor():
    links = [ExtractedLink("l1", "https://random-hosting-123.com/login", "https://google.com/login", "html", None)]
    email = make_email_with_links(links)
    out = analyze_links(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "AUTH_LIKE_PATH_DETECTED" in codes
    assert "CREDENTIAL_PHISHING_LINK" in codes