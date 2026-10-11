"""
Unit tests for Section 8: Security, Governance & Legal Compliance.
Verifies license notices, security policies, threat models, secret scanner,
and softened Section 63 BSA legal claims.
"""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_license_and_notice_exist():
    license_file = REPO_ROOT / "LICENSE"
    notice_file = REPO_ROOT / "NOTICE"

    assert license_file.is_file(), "LICENSE file must exist in repository root"
    assert notice_file.is_file(), "NOTICE file must exist in repository root"

    license_content = license_file.read_text(encoding="utf-8")
    assert "Apache License" in license_content
    assert "Version 2.0" in license_content
    assert "Copyright 2026 HopZero" in license_content

    notice_content = notice_file.read_text(encoding="utf-8")
    assert "HopZero Email Forensics & BotChain Tool Suite" in notice_content
    assert "FastAPI" in notice_content
    assert "MaxMind" in notice_content
    assert "Hermes 3" in notice_content


def test_security_and_governance_docs():
    security_md = REPO_ROOT / "SECURITY.md"
    contributing_md = REPO_ROOT / "CONTRIBUTING.md"
    threat_model = REPO_ROOT / "docs" / "THREAT_MODEL.md"
    responsible_use = REPO_ROOT / "docs" / "RESPONSIBLE_USE.md"
    tos = REPO_ROOT / "docs" / "TERMS_OF_SERVICE.md"
    privacy = REPO_ROOT / "docs" / "PRIVACY_POLICY.md"

    for doc in [security_md, contributing_md, threat_model, responsible_use, tos, privacy]:
        assert doc.is_file(), f"Document {doc.name} must exist"
        content = doc.read_text(encoding="utf-8")
        assert len(content) > 100, f"{doc.name} must contain meaningful policy documentation"


def test_bsa_section_63_legal_claim_softened():
    """
    DEC-016 and Section 8 legal compliance invariant:
    Ensure that Section 63 BSA claims explicitly disclaim that HopZero certifies legal admissibility,
    and state that it is structured to support the certification process.
    """
    tos_content = (REPO_ROOT / "docs" / "TERMS_OF_SERVICE.md").read_text(encoding="utf-8")
    privacy_content = (REPO_ROOT / "docs" / "PRIVACY_POLICY.md").read_text(encoding="utf-8")
    resp_use_content = (REPO_ROOT / "docs" / "RESPONSIBLE_USE.md").read_text(encoding="utf-8")

    expected_softened_phrase = "structured to support the applicable Section 63"
    disclaimer_phrase = "HopZero does not certify legal admissibility"

    for doc_name, content in [("TERMS_OF_SERVICE", tos_content), ("PRIVACY_POLICY", privacy_content), ("RESPONSIBLE_USE", resp_use_content)]:
        assert expected_softened_phrase in content, f"{doc_name} must contain softened Section 63 phrase"
        assert disclaimer_phrase in content, f"{doc_name} must explicitly disclaim certification of legal admissibility"


def test_secrets_and_pii_scanner_passes():
    """Runs scripts/scan_secrets_and_pii.py to ensure zero secrets in active codebase."""
    scanner_path = REPO_ROOT / "scripts" / "scan_secrets_and_pii.py"
    assert scanner_path.is_file()

    result = subprocess.run([sys.executable, str(scanner_path)], capture_output=True, text=True)
    assert result.returncode == 0, f"Secret scanner failed: {result.stdout}\n{result.stderr}"
    assert "No unredacted secrets or credentials detected" in result.stdout
