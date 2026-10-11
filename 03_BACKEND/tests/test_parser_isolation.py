"""
Tests for HZ7: Parser and Attachment Isolation.
===============================================

Validates that untrusted EML parsing and attachment processing:
1. Is strictly isolated and cannot hang or crash the server.
2. Defends against deep MIME recursion bombs (depth capped at 20).
3. Defends against attachment inflation (10 MB per part, 25 MB cumulative, 50 parts).
4. Handles timeout gracefully with is_truncated=True and warning signal.
5. Handles worker crash/death gracefully with is_truncated=True and warning signal.
6. Parses canonical legitimate emails identically to direct parsing.
"""

import email.message
import sys
from pathlib import Path

import pytest

_repo_root = Path(__file__).resolve().parents[2]
_forensics_dir = str(_repo_root / "02_FORENSICS")
if _forensics_dir not in sys.path:
    sys.path.insert(0, _forensics_dir)

from hopzero.core.isolation import (
    parse_eml_isolated,
    SIMULATION_TIMEOUT_MARKER,
    SIMULATION_CRASH_MARKER,
    MAX_MIME_RECURSION_DEPTH,
    MAX_ATTACHMENTS_COUNT,
    MAX_ATTACHMENT_BYTES,
    MAX_TOTAL_ATTACHMENT_BYTES,
)
from hopzero.core.models import SignalState
from hopzero_forensics.parser import parse_eml
from hopzero_forensics.evidence_normalizer import normalize_email


# ---------------------------------------------------------------------------
# 1. Parity with direct parser for legitimate emails
# ---------------------------------------------------------------------------

def test_legitimate_canonical_email_parses_identically():
    raw_email = (
        b"From: Alice Security <alice@legit.corp>\r\n"
        b"To: Bob <bob@recipient.org>\r\n"
        b"Subject: Quarterly Security Advisory\r\n"
        b"Date: Mon, 12 Sep 2025 09:30:00 +0000\r\n"
        b"Message-ID: <msg-12345@legit.corp>\r\n"
        b"Received: from mail.legit.corp (mail.legit.corp [198.51.100.10]) by mx.recipient.org with SMTP id 999; Mon, 12 Sep 2025 09:30:05 +0000\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Please review the attached patch details at https://portal.legit.corp/patches\r\n"
    )

    direct = parse_eml(raw_email, artifact_id="art-parity-1", parse_instance_id="inst-1")
    isolated = parse_eml_isolated(
        raw_email,
        artifact_id="art-parity-1",
        parse_instance_id="inst-1",
        timeout=10.0,
        isolation_mode="subprocess",
    )

    assert isolated.subject == direct.subject
    assert isolated.message_id == direct.message_id
    assert isolated.date_raw == direct.date_raw
    assert len(isolated.from_addresses) == len(direct.from_addresses)
    assert isolated.from_addresses[0].address == direct.from_addresses[0].address
    assert len(isolated.to_addresses) == len(direct.to_addresses)
    assert isolated.to_addresses[0].address == direct.to_addresses[0].address
    assert isolated.body.text_plain == direct.body.text_plain
    assert len(isolated.body.links) == len(direct.body.links)
    assert isolated.body.links[0].href == direct.body.links[0].href
    assert len(isolated.received_chain_raw) == len(direct.received_chain_raw)
    assert isolated.received_chain_raw[0].observed_ip == direct.received_chain_raw[0].observed_ip
    assert isolated.is_truncated is False


# ---------------------------------------------------------------------------
# 2. MIME recursion bomb defense
# ---------------------------------------------------------------------------

def test_mime_recursion_bomb_is_bounded_without_stack_overflow():
    """
    Constructs a deeply nested multipart MIME structure (35 levels deep).
    Parser must cap traversal at depth 20 and record MIME_DEPTH_EXCEEDED warning.
    """
    # Build 35 nested multipart messages
    inner = email.message.EmailMessage()
    inner.set_content("Deep payload at center")

    current = inner
    for i in range(35):
        parent = email.message.EmailMessage()
        parent["Subject"] = f"Nesting level {i}"
        parent["From"] = "attacker@bomb.xyz"
        parent["To"] = "victim@target.local"
        parent.make_mixed()
        parent.attach(current)
        current = parent

    raw_bomb = current.as_bytes()

    parsed = parse_eml_isolated(
        raw_bomb,
        artifact_id="art-bomb-1",
        timeout=10.0,
        isolation_mode="subprocess",
    )

    # Must complete without crashing or hanging
    assert parsed.artifact_id == "art-bomb-1"
    assert any("MIME_DEPTH_EXCEEDED" in w for w in parsed.parse_warnings)


# ---------------------------------------------------------------------------
# 3. Attachment resource caps (part size, cumulative size, count)
# ---------------------------------------------------------------------------

def test_attachment_part_size_capped():
    """
    Construct an email with an attachment exceeding 10 MB limit.
    """
    # 11 MB dummy attachment content
    oversized_data = b"X" * (11 * 1024 * 1024)

    msg = email.message.EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Oversized Attachment Test"
    msg.set_content("Check attached large file")
    msg.add_attachment(
        oversized_data,
        maintype="application",
        subtype="octet-stream",
        filename="huge_payload.bin",
    )
    raw = msg.as_bytes()

    parsed = parse_eml_isolated(raw, artifact_id="art-oversized-1", timeout=15.0, isolation_mode="in_process")

    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "huge_payload.bin"
    assert parsed.attachments[0].parse_state == SignalState.UNAVAILABLE
    assert any("ATTACHMENT_PART_SIZE_EXCEEDED" in w for w in parsed.parse_warnings)


def test_cumulative_attachment_size_capped():
    """
    Construct an email with three 9 MB attachments (total 27 MB > 25 MB limit).
    """
    msg = email.message.EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Cumulative Attachment Test"
    msg.set_content("Three large attachments")

    part_9mb = b"A" * (9 * 1024 * 1024)
    for i in range(3):
        msg.add_attachment(
            part_9mb,
            maintype="application",
            subtype="octet-stream",
            filename=f"part_{i}.bin",
        )
    raw = msg.as_bytes()

    parsed = parse_eml_isolated(raw, artifact_id="art-cumul-1", timeout=15.0, isolation_mode="in_process")

    assert len(parsed.attachments) == 3
    # First 2 are 9MB + 9MB = 18MB <= 25MB (PRESENT)
    assert parsed.attachments[0].parse_state == SignalState.PRESENT
    assert parsed.attachments[1].parse_state == SignalState.PRESENT
    # 3rd would exceed 25MB cumulative -> UNAVAILABLE with warning
    assert parsed.attachments[2].parse_state == SignalState.UNAVAILABLE
    assert any("ATTACHMENT_TOTAL_SIZE_EXCEEDED" in w for w in parsed.parse_warnings)


def test_attachment_count_capped():
    """
    Construct an email with 55 small attachments (exceeding 50 limit).
    """
    msg = email.message.EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Attachment Count Flood"
    msg.set_content("Many small attachments")

    for i in range(55):
        msg.add_attachment(
            b"tiny",
            maintype="text",
            subtype="plain",
            filename=f"file_{i}.txt",
        )
    raw = msg.as_bytes()

    parsed = parse_eml_isolated(raw, artifact_id="art-count-1", timeout=15.0, isolation_mode="in_process")

    assert len(parsed.attachments) == 50
    assert any("ATTACHMENT_COUNT_EXCEEDED" in w for w in parsed.parse_warnings)


# ---------------------------------------------------------------------------
# 4. Timeout and worker crash recovery
# ---------------------------------------------------------------------------

def test_parser_timeout_simulation_returns_fallback_gracefully():
    """
    Simulates a hung worker (e.g. catastrophic regex backtrack or infinite loop).
    The subprocess must be terminated cleanly after the timeout and return a fallback CanonicalEmail.
    """
    result = parse_eml_isolated(
        SIMULATION_TIMEOUT_MARKER,
        artifact_id="art-timeout-test",
        parse_instance_id="inst-timeout",
        timeout=0.6,
        isolation_mode="subprocess",
    )

    assert result.artifact_id == "art-timeout-test"
    assert result.id == "inst-timeout"
    assert result.is_truncated is True
    assert any("PARSER_TIMEOUT" in w for w in result.parse_warnings)
    # Must have valid empty structure
    assert result.headers == []
    assert result.attachments == []
    assert result.body.text_plain is None


def test_parser_crash_recovery_returns_fallback_gracefully():
    """
    Simulates a hard worker crash (e.g. segfault / exit code 139).
    The parent process must catch this and return a fallback CanonicalEmail.
    """
    result = parse_eml_isolated(
        SIMULATION_CRASH_MARKER,
        artifact_id="art-crash-test",
        parse_instance_id="inst-crash",
        timeout=5.0,
        isolation_mode="subprocess",
    )

    assert result.artifact_id == "art-crash-test"
    assert result.id == "inst-crash"
    assert result.is_truncated is True
    assert any("PARSER_CRASH" in w for w in result.parse_warnings)
    assert result.headers == []
    assert result.attachments == []


# ---------------------------------------------------------------------------
# 5. Fallback email flows safely through evidence normalizer
# ---------------------------------------------------------------------------

def test_fallback_email_flows_through_evidence_normalizer_safely():
    """
    Validates that a fallback CanonicalEmail (from timeout or crash)
    passes through normalize_email without any exceptions.
    """
    fallback = parse_eml_isolated(
        SIMULATION_CRASH_MARKER,
        artifact_id="art-norm-safe",
        timeout=5.0,
        isolation_mode="subprocess",
    )

    norm = normalize_email(fallback)
    assert norm.source_canonical_email_id == fallback.id
    assert norm.source_artifact_id == "art-norm-safe"
    assert norm.fields == []
