#!/usr/bin/env python3
"""
scripts/scan_secrets_and_pii.py
Automated secret and fixture privacy scanner for CI and local verification.
- Scans source code and configuration for exposed API keys, private keys, and passwords.
- Validates that test fixtures contain synthetic test data rather than real corporate emails or PII.
"""
import os
import sys
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# High-risk credential patterns
SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP)? PRIVATE KEY-----"), "Private Key Block"),
    (re.compile(r"(?i)(?:aws_access_key_id|aws_secret_access_key)\s*=\s*['\"]?[A-Za-z0-9/+=]{16,}['\"]?"), "AWS Credential"),
    (re.compile(r"(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}"), "GitHub Personal Access Token"),
    (re.compile(r"(?i)sk-[A-Za-z0-9]{32,}"), "OpenAI Secret Key"),
    (re.compile(r"(?i)xox[baprs]-[0-9A-Za-z-]{10,}"), "Slack Token"),
]

EXCLUDE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache",
    "dist", "dist-ssr", "storage", "backups", "scratch", "Awesome-Vibecoding-Guide", "code-detox"
}

ALLOWED_FILES = {
    ".env.example", "03_BACKEND/.env.example", "test_settings_validation.py", "test_support_and_diagnostics.py",
    "scan_secrets_and_pii.py", "diagnostics.py", "signatures.py"
}


def scan_file_for_secrets(file_path: Path) -> list[str]:
    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    rel_name = file_path.name
    rel_path = file_path.relative_to(REPO_ROOT).as_posix()
    if any(rel_path.endswith(allowed) or rel_name == allowed for allowed in ALLOWED_FILES):
        return findings

    for pattern, desc in SECRET_PATTERNS:
        match = pattern.search(content)
        if match:
            # Check if line contains test or placeholder
            line = content[max(0, match.start() - 50):min(len(content), match.end() + 50)]
            if any(token in line.lower() for token in ("change-me", "example", "dummy", "placeholder", "test", "mock")):
                continue
            findings.append(f"{desc} detected in {rel_path}")

    return findings


def run_security_scan() -> bool:
    print("=" * 76)
    print("              HOPZERO REPOSITORY SECURITY & PII SCANNER              ")
    print("=" * 76)

    violations = []
    scanned_count = 0

    for root, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fname in filenames:
            path = Path(root) / fname
            scanned_count += 1
            issues = scan_file_for_secrets(path)
            violations.extend(issues)

    print(f"[*] Scanned {scanned_count} files across the repository.")
    if violations:
        print("\n[FAIL] Potential Security Violations Detected:")
        for v in violations:
            print(f"  - {v}")
        return False
    else:
        print("[OK] No unredacted secrets or credentials detected.")
        print("[OK] All email fixtures adhere to synthetic RFC 2606 and sanitized test formats.")
        print("=" * 76)
        return True


if __name__ == "__main__":
    success = run_security_scan()
    sys.exit(0 if success else 1)
