import pytest
from datetime import datetime, timezone
from hopzero_forensics.interfaces import CanonicalEmail, EmailBody, ExtractedAttachment, SignalState
from hopzero_forensics.analyzers.attachments import analyze_attachments

def make_email_with_attachments(attachments):
    return CanonicalEmail(
        id="test-parse-att-1",
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
        attachments=attachments,
        subject="Test",
        date_raw="",
        date_parsed=datetime.now(timezone.utc),
    )

def test_benign_pdf_attachment():
    att = ExtractedAttachment("a1", "report.pdf", "application/pdf", 50000, "hash1", "attachment", False, False, SignalState.PRESENT)
    email = make_email_with_attachments([att])
    out = analyze_attachments(email)
    assert len(out.candidates) == 0

def test_double_extension_detected():
    att = ExtractedAttachment("a1", "invoice.pdf.exe", "application/octet-stream", 100000, "hash1", "attachment", False, False, SignalState.PRESENT)
    email = make_email_with_attachments([att])
    out = analyze_attachments(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "DOUBLE_COMPOUND_EXTENSION" in codes
    assert "SUSPICIOUS_ATTACHMENT" in codes
    c = next(c for c in out.candidates if c.qualification_code == "DOUBLE_COMPOUND_EXTENSION")
    assert c.strength == "Strong"

def test_macro_enabled_document_detected():
    att = ExtractedAttachment("a1", "quarterly_earnings.xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", 200000, "hash1", "attachment", False, False, SignalState.PRESENT)
    email = make_email_with_attachments([att])
    out = analyze_attachments(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "MACRO_ENABLED_DOCUMENT" in codes
    c = next(c for c in out.candidates if c.qualification_code == "MACRO_ENABLED_DOCUMENT")
    assert c.strength == "Moderate"

def test_executable_inside_archive_detected():
    att = ExtractedAttachment("a1", "setup.exe", "application/x-msdos-program", 50000, "hash1", "attachment", False, True, SignalState.PRESENT)
    email = make_email_with_attachments([att])
    out = analyze_attachments(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "EXECUTABLE_IN_ARCHIVE" in codes

def test_urgency_filename_detected():
    att = ExtractedAttachment("a1", "URGENT_OVERDUE_PAYMENT.pdf", "application/pdf", 30000, "hash1", "attachment", False, False, SignalState.PRESENT)
    email = make_email_with_attachments([att])
    out = analyze_attachments(email)
    codes = [c.qualification_code for c in out.candidates]
    assert "URGENCY_AUTHORITY_FILENAME" in codes
    c = next(c for c in out.candidates if c.qualification_code == "URGENCY_AUTHORITY_FILENAME")
    assert c.strength == "Weak"