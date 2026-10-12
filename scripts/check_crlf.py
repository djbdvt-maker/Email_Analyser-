#!/usr/bin/env python3
"""
scripts/check_crlf.py - Enforce Unix LF line endings across repository text files.

Scans tracked git files (or workspace files) to ensure no unwanted CRLF endings exist.
Exemptions:
- Binary files (*.png, *.eml, *.db, *.pdf, etc.)
- Windows shell scripts (*.bat, *.cmd, *.ps1) which require CRLF.

Usage:
    python scripts/check_crlf.py          # Check and report violations (exit 1 if CRLF found)
    python scripts/check_crlf.py --fix    # Automatically convert CRLF to LF in text files
"""
import sys
import subprocess
from pathlib import Path

BINARY_EXTENSIONS = {
    ".eml", ".msg",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf",
    ".db", ".sqlite", ".sqlite3",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".7z",
    ".gguf", ".woff", ".woff2", ".ttf", ".eot",
    ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyd"
}

ALLOWED_CRLF_EXTENSIONS = {
    ".bat", ".cmd", ".ps1"
}

EXEMPT_DIRECTORIES = {
    Path("01_REGISTRY/releases"),
}


def is_binary_content(data: bytes) -> bool:
    """Heuristic check for binary content (null bytes)."""
    return b"\x00" in data[:8192]


def get_tracked_files(root: Path) -> list[Path]:
    """Get tracked files from git, or fall back to scanning the filesystem."""
    try:
        res = subprocess.run(
            ["git", "ls-files"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True
        )
        return [root / line.strip() for line in res.stdout.splitlines() if line.strip()]
    except Exception:
        # Fallback to directory walk
        files = []
        for p in root.rglob("*"):
            if p.is_file() and not any(part.startswith(".") for part in p.parts):
                files.append(p)
        return files


def main():
    fix_mode = "--fix" in sys.argv
    root = Path(__file__).resolve().parent.parent
    files = get_tracked_files(root)

    crlf_files = []
    fixed_count = 0

    for file_path in files:
        if not file_path.exists() or file_path.is_dir():
            continue

        rel_path = file_path.relative_to(root)
        if any(exempt_dir in rel_path.parents for exempt_dir in EXEMPT_DIRECTORIES):
            continue

        ext = file_path.suffix.lower()
        if ext in BINARY_EXTENSIONS or ext in ALLOWED_CRLF_EXTENSIONS:
            continue

        try:
            content = file_path.read_bytes()
        except Exception:
            continue

        if is_binary_content(content):
            continue

        if b"\r\n" in content:
            rel_path = file_path.relative_to(root)
            crlf_files.append(rel_path)
            if fix_mode:
                new_content = content.replace(b"\r\n", b"\n")
                file_path.write_bytes(new_content)
                fixed_count += 1

    if fix_mode:
        print(f"[check_crlf] Converted {fixed_count} file(s) from CRLF to LF.")
        return 0

    if crlf_files:
        print(f"[check_crlf] FAIL: Found {len(crlf_files)} text file(s) with CRLF line endings:")
        for f in crlf_files[:30]:
            print(f"  - {f}")
        if len(crlf_files) > 30:
            print(f"  ... and {len(crlf_files) - 30} more.")
        print("\nRun 'python scripts/check_crlf.py --fix' to convert them to LF.")
        return 1

    print(f"[check_crlf] PASS: All tracked text files use LF line endings ({len(files)} files checked).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
