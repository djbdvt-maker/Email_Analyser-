import os

from hopzero_forensics.interfaces import SignalState
from hopzero_forensics.parser import parse_eml_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture(name: str) -> str:
    return os.path.join(FIXTURES, name)


def test_parses_basic_headers_and_addresses():
    email = parse_eml_file(_fixture("legit_gmail_to_gmail.eml"), artifact_id="art-1")
    assert email.subject == "Weekend plans"
    assert email.message_id == "<CAExample1234567890@mail.gmail.com>"
    assert len(email.from_addresses) == 1
    assert email.from_addresses[0].address == "bob.sender@gmail.com"
    assert email.from_addresses[0].parse_state == SignalState.PRESENT
    assert len(email.to_addresses) == 1
    assert email.to_addresses[0].address == "alice.recipient@gmail.com"


def test_received_chain_is_extracted_in_order():
    email = parse_eml_file(_fixture("legit_gmail_to_gmail.eml"), artifact_id="art-2")
    assert len(email.received_chain_raw) == 3
    # sequence_index should be 0-based and ascending in header order (newest first)
    assert [h.sequence_index for h in email.received_chain_raw] == [0, 1, 2]
    assert email.received_chain_raw[1].by_claim is not None
    assert "mx.google.com" in email.received_chain_raw[1].by_claim


def test_no_received_chain_is_empty_not_crashed():
    email = parse_eml_file(_fixture("no_received_chain.eml"), artifact_id="art-3")
    assert email.received_chain_raw == []
    assert email.is_truncated is False


def test_body_text_plain_extracted():
    email = parse_eml_file(_fixture("legit_gmail_to_gmail.eml"), artifact_id="art-4")
    assert email.body.text_plain is not None
    assert "Saturday" in email.body.text_plain


def test_raw_headers_preserve_original_line_and_sequence():
    email = parse_eml_file(_fixture("legit_gmail_to_gmail.eml"), artifact_id="art-5")
    assert len(email.headers) > 0
    for i, h in enumerate(email.headers):
        assert h.sequence_index == i
        assert h.raw_line  # never empty/destroyed


def test_malformed_received_header_does_not_crash_parser():
    email = parse_eml_file(_fixture("generic_malformed_header.eml"), artifact_id="art-6")
    assert len(email.received_chain_raw) == 2
    malformed_hop = email.received_chain_raw[1]
    assert malformed_hop.parse_state == SignalState.UNAVAILABLE
    assert malformed_hop.malformed_reason is not None


def test_html_link_extraction_and_sanitization():
    raw = (
        b"From: a@example.com\r\n"
        b"To: b@example.com\r\n"
        b"Subject: test\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b'<html><body><script>alert(1)</script>'
        b'<a href="http://phish.example/login">Verify your account</a>'
        b"</body></html>"
    )
    from hopzero_forensics.parser import parse_eml

    email = parse_eml(raw, artifact_id="art-7")
    assert email.body.html_available is True
    assert "<script>" not in (email.body.html_sanitized or "")
    hrefs = [l.href for l in email.body.links]
    assert "http://phish.example/login" in hrefs


def test_attachment_sha256_and_size_present():
    raw = (
        b"From: a@example.com\r\n"
        b"To: b@example.com\r\n"
        b"Subject: with attachment\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="BOUNDARY"\r\n'
        b"\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"body text\r\n"
        b"--BOUNDARY\r\n"
        b'Content-Type: application/octet-stream; name="payload.bin"\r\n'
        b'Content-Disposition: attachment; filename="payload.bin"\r\n'
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"aGVsbG8gd29ybGQ=\r\n"
        b"--BOUNDARY--\r\n"
    )
    from hopzero_forensics.parser import parse_eml

    email = parse_eml(raw, artifact_id="art-8")
    assert len(email.attachments) == 1
    att = email.attachments[0]
    assert att.filename == "payload.bin"
    assert att.sha256 is not None
    assert att.size_bytes == len(b"hello world")
