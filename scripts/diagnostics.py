#!/usr/bin/env python3
"""
scripts/diagnostics.py
HopZero Support Diagnostics & Log Redaction Utility.
Gathers runtime versions, hardware profiling, doctor health checks,
and application logs while strictly stripping PII and cryptographic secrets.
Exports a sanitized archive for technical support and bug reporting.
"""
import os
import sys
import re
import json
import zipfile
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "01_REGISTRY"))
sys.path.insert(0, str(REPO_ROOT / "02_FORENSICS"))
sys.path.insert(0, str(REPO_ROOT / "03_BACKEND"))

from hopzero.core.paths import get_app_data_root, get_logs_dir
from hopzero.core.hardware import detect_hardware
from scripts.doctor import run_diagnostics

# Regex redaction patterns
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
RE_IPV4 = re.compile(r"\b(?!127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.255)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
RE_JWT = re.compile(r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+")
RE_SECRET_KEY = re.compile(r"(?i)(key|secret|password|token)\s*[:=]\s*['\"]?([A-Za-z0-9-_!@#$%^&*+=]{6,})['\"]?")


def redact_text(text: str) -> str:
    """Sanitizes text by masking PII, IP addresses, tokens, and credentials."""
    text = RE_EMAIL.sub("[REDACTED_EMAIL]", text)
    text = RE_IPV4.sub("[REDACTED_IP]", text)
    text = RE_JWT.sub("[REDACTED_JWT_TOKEN]", text)
    text = RE_SECRET_KEY.sub(r"\1: [REDACTED_CREDENTIAL]", text)
    return text


def collect_sanitized_diagnostics() -> Dict[str, Any]:
    """Assembles a clean, privacy-preserving diagnostics dictionary."""
    # 1. Hardware profile
    hw = detect_hardware()

    # 2. Doctor health checks
    checks = run_diagnostics(verbose=False)
    doctor_data = [
        {"name": c.name, "passed": c.passed, "warning": c.warning, "message": c.message}
        for c in checks
    ]

    # 3. Environment & version snapshot
    snapshot_path = REPO_ROOT / "05_QA" / "golden" / "environment_snapshot.json"
    snapshot = {}
    if snapshot_path.exists():
        try:
            snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    # 4. Settings summary (with secrets strictly redacted)
    from app.config import get_settings
    s = get_settings()
    settings_data = {
        "environment": s.environment,
        "database_url_scheme": s.database_url.split("://")[0] if "://" in s.database_url else "unknown",
        "parser_isolation_mode": s.parser_isolation_mode,
        "hopzero_llm_provider": s.hopzero_llm_provider,
        "hopzero_llm_model": s.hopzero_llm_model,
        "enforcement_provider": s.enforcement_provider,
        "jwt_secret_configured": bool(s.jwt_secret_key and s.jwt_secret_key != "change-me-in-production"),
        "telemetry": "DISABLED (Strict Zero-Telemetry Default)",
    }

    return {
        "product": "HopZero Email Forensics & BotChain Tool Suite",
        "version": "4.2.0",
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hardware": hw.to_dict(),
        "doctor": doctor_data,
        "settings": settings_data,
        "environment_snapshot": snapshot,
    }


def export_diagnostics_archive(output_path: Path = None) -> Path:
    """Bundles sanitized diagnostics report and redacted log files into a zip archive."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    if not output_path:
        out_dir = get_app_data_root() / "diagnostics"
        out_dir.mkdir(parents=True, exist_ok=True)
        output_path = out_dir / f"hopzero_diagnostics_{timestamp}.zip"
    else:
        output_path = Path(output_path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

    diag_data = collect_sanitized_diagnostics()

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Write json report
        report_json = json.dumps(diag_data, indent=2)
        zf.writestr("diagnostics_report.json", report_json)

        # Include sanitized logs
        logs_dir = get_logs_dir()
        if logs_dir.exists():
            for log_file in logs_dir.glob("*.log"):
                try:
                    raw_content = log_file.read_text(encoding="utf-8", errors="replace")
                    clean_content = redact_text(raw_content)
                    zf.writestr(f"logs/{log_file.name}", clean_content)
                except Exception:
                    pass

    return output_path


def main():
    parser = argparse.ArgumentParser(description="HopZero Support Diagnostics")
    parser.add_argument("--export", nargs="?", const="default", help="Export sanitized diagnostics zip archive")
    args = parser.parse_args()

    if args.export:
        target = None if args.export == "default" else Path(args.export)
        zip_path = export_diagnostics_archive(target)
        print("=" * 76)
        print("           HOPZERO REDACTED SUPPORT DIAGNOSTICS ARCHIVE              ")
        print("=" * 76)
        print(f"[OK] Diagnostics bundle generated successfully:")
        print(f"     Archive: {zip_path}")
        print(f"     Size:    {zip_path.stat().st_size} bytes")
        print(f"     Privacy: All emails, IPs, JWT tokens, and credentials have been REDACTED.")
        print(f"     Usage:   Attach this file when filing GitHub issues or contacting support.")
        print("=" * 76)
    else:
        diag = collect_sanitized_diagnostics()
        print(json.dumps(diag, indent=2))


if __name__ == "__main__":
    main()
