#!/usr/bin/env python3
"""
scripts/check_claims.py - Enforce technical precision and prevent unmeasured marketing claims.

Checks documentation and text files across the repository to verify that:
1. License declarations are consistent (Apache-2.0 across pyproject.toml, LICENSE, README, NOTICE).
2. Absolute, unmeasured, or misleading marketing claims are not present.
3. Legal phrasing correctly notes that HopZero does not certify legal admissibility.

Usage:
    python scripts/check_claims.py
"""
import sys
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Forbidden marketing claims and unmeasured phrases in user-facing docs
FORBIDDEN_PATTERNS = [
    (r"\b0\s+cloud\s+leaks\b", "Unqualified absolute claim '0 cloud leaks' (qualify: on-premises by default; network lookups optional)."),
    (r"\b0\s+score\s+drift\b", "Unqualified claim '0 score drift' (qualify: deterministic scoring verified by regression fixtures)."),
    (r"\b100%\s+byte-identical\b", "Unqualified claim '100% byte-identical' (qualify: verified against included test fixtures)."),
    (r"\b100%\s+on-premises\s+determinism\b", "Unqualified claim '100% on-premises determinism' (qualify: on-premises determinism)."),
    (r"\b\d+x\s+faster\b", "Unmeasured comparison claim (e.g. '10x faster')."),
    (r"\btok/s\b", "Unmeasured throughput claim 'tok/s'."),
    (r"\bguarantees?\s+court\s+admissibility\b", "Legally inaccurate claim (HopZero does not certify legal admissibility)."),
    (r"\bcertifies\s+legal\s+admissibility\b", "Legally inaccurate claim (HopZero does not certify legal admissibility)."),
]

DOC_EXTENSIONS = {".md", ".rst", ".txt"}
EXEMPT_FILES = {
    REPO_ROOT / "docs" / "FIX_LOG.md",
    REPO_ROOT / "docs" / "DECISIONS.md",
    REPO_ROOT / "CHANGELOG.md",
    Path(__file__).resolve(),
}


def check_license_consistency() -> list[str]:
    errors = []

    # 1. pyproject.toml
    pyproject_path = REPO_ROOT / "pyproject.toml"
    if pyproject_path.exists():
        content = pyproject_path.read_text(encoding="utf-8")
        if 'license = { text = "Apache-2.0" }' not in content and 'license = "Apache-2.0"' not in content:
            errors.append("pyproject.toml does not declare Apache-2.0 license.")

    # 2. LICENSE
    license_path = REPO_ROOT / "LICENSE"
    if not license_path.exists():
        errors.append("Root LICENSE file is missing.")
    else:
        content = license_path.read_text(encoding="utf-8")
        if "Apache License" not in content or "Version 2.0" not in content:
            errors.append("Root LICENSE file is not Apache License Version 2.0.")

    # 3. NOTICE
    notice_path = REPO_ROOT / "NOTICE"
    if not notice_path.exists():
        errors.append("Root NOTICE file is missing.")

    # 4. README.md
    readme_path = REPO_ROOT / "README.md"
    if readme_path.exists():
        content = readme_path.read_text(encoding="utf-8")
        if "Apache License, Version 2.0" not in content and "Apache 2.0" not in content:
            errors.append("README.md does not reference Apache License 2.0.")

    return errors


def get_tracked_doc_files() -> list[Path]:
    import subprocess
    try:
        res = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True)
        tracked = set(res.stdout.splitlines())
        res_status = subprocess.run(["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True)
        for line in res_status.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                tracked.add(parts[-1])
        files = []
        for line in tracked:
            p = REPO_ROOT / line
            if p.suffix.lower() in DOC_EXTENSIONS and p not in EXEMPT_FILES and p.exists():
                files.append(p)
        return files
    except Exception:
        return [p for p in REPO_ROOT.rglob("*") if p.suffix.lower() in DOC_EXTENSIONS and p not in EXEMPT_FILES and not any(part.startswith(".") for part in p.parts)]


def check_claims_in_files() -> list[str]:
    errors = []

    for path in get_tracked_doc_files():
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue

        for pattern, explanation in FORBIDDEN_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                rel = path.relative_to(REPO_ROOT)
                errors.append(f"{rel}: Match '{matches[0]}' violated rule: {explanation}")

    return errors


def main():
    print("[check_claims] Verifying license consistency and technical precision in claims...")
    license_errors = check_license_consistency()
    claims_errors = check_claims_in_files()

    all_errors = license_errors + claims_errors
    if all_errors:
        print(f"[check_claims] FAIL: Found {len(all_errors)} violation(s):")
        for err in all_errors:
            print(f"  - {err}")
        return 1

    print("[check_claims] PASS: All licenses consistent (Apache-2.0) and all claims verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
