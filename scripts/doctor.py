#!/usr/bin/env python3
"""
scripts/doctor.py
HopZero Commercial Health Diagnostic Utility ("doctor").
Checks runtime versions, services, ports, disk, resident models, forensic registry integrity,
and provides clear, actionable remediation hints.
"""
import os
import sys
import shutil
import socket
import urllib.request
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "01_REGISTRY"))
sys.path.insert(0, str(REPO_ROOT / "02_FORENSICS"))
sys.path.insert(0, str(REPO_ROOT / "03_BACKEND"))

from hopzero.core.paths import get_app_data_root, get_artifacts_dir, get_default_sqlite_db_path
from hopzero.core.registry import load_registry


class DoctorCheck:
    def __init__(self, name: str):
        self.name = name
        self.passed = True
        self.warning = False
        self.message = ""
        self.fix_hint = ""


def check_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """Returns True if the port is open/listening."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def run_diagnostics(verbose: bool = True) -> list[DoctorCheck]:
    checks = []

    # 1. Python Version
    c = DoctorCheck("Python Runtime")
    v = sys.version_info
    v_str = f"{v.major}.{v.minor}.{v.micro}"
    if v.major == 3 and v.minor == 12:
        c.message = f"Python {v_str} (Supported: 3.12.x)"
    else:
        c.passed = False
        c.message = f"Python {v_str} detected. Requires Python 3.12.x."
        c.fix_hint = "Install Python 3.12.10 from https://www.python.org/downloads/ or via winget: 'winget install Python.Python.3.12'"
    checks.append(c)

    # 2. Node.js & NPM
    c = DoctorCheck("Node.js Environment")
    node_bin = shutil.which("node")
    npm_bin = shutil.which("npm")
    if node_bin and npm_bin:
        c.message = f"Node executable found at {node_bin}"
    else:
        c.warning = True
        c.message = "Node.js or npm not found in system PATH (required for frontend dev server)."
        c.fix_hint = "Install Node.js LTS (v20+ or v24) from https://nodejs.org or run 'winget install OpenJS.NodeJS.LTS'"
    checks.append(c)

    # 3. Disk Space
    c = DoctorCheck("Available Disk Space")
    app_data = get_app_data_root()
    total, used, free = shutil.disk_usage(app_data)
    free_gb = free / (1024 ** 3)
    if free_gb >= 5.0:
        c.message = f"{free_gb:.1f} GB available on {app_data.drive or 'root drive'} (>= 5.0 GB recommended)"
    elif free_gb >= 1.0:
        c.warning = True
        c.message = f"Low disk space: {free_gb:.1f} GB available. Minimum recommended is 5.0 GB."
        c.fix_hint = f"Free up disk space on drive {app_data.drive or 'root'} to ensure email evidence storage."
    else:
        c.passed = False
        c.message = f"Critical low disk space: only {free_gb:.2f} GB free."
        c.fix_hint = "Free up disk space before processing large email forensic archives."
    checks.append(c)

    # 4. Storage & Application Directories
    c = DoctorCheck("Application Directories & Permissions")
    try:
        app_data = get_app_data_root()
        artifacts = get_artifacts_dir()
        db_path = get_default_sqlite_db_path()
        test_file = app_data / ".doctor_test_write"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink()
        c.message = f"Writable app data directory at: {app_data}"
    except Exception as e:
        c.passed = False
        c.message = f"Failed to access or write to application directory: {e}"
        c.fix_hint = "Verify read/write permissions on the application data directory or set HOPZERO_DATA_DIR to a writable directory."
    checks.append(c)

    # 5. Database Connectivity
    c = DoctorCheck("Database Connectivity")
    from app.config import get_settings
    settings = get_settings()
    if settings.database_url.startswith("sqlite"):
        c.message = f"SQLite database configured at: {settings.database_url}"
    elif settings.database_url.startswith("postgresql"):
        # Check if port 5432 is responding
        if check_port("localhost", 5432):
            c.message = "PostgreSQL service is responding on localhost:5432"
        else:
            c.passed = False
            c.message = "PostgreSQL service not reachable on localhost:5432"
            c.fix_hint = "Start PostgreSQL service or run docker-compose up -d postgres"
    checks.append(c)

    # 6. Ollama Daemon & Resident Local LLM
    c = DoctorCheck("Local LLM Service (Ollama)")
    ollama_online = check_port("127.0.0.1", 11434)
    if ollama_online:
        try:
            req = urllib.request.Request("http://127.0.0.1:11434/api/tags")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", [])]
                target_model = settings.hopzero_llm_model  # "hermes3:3b"
                found = any(target_model in m for m in models)
                if found:
                    c.message = f"Ollama daemon online at 127.0.0.1:11434 with model '{target_model}' ready."
                else:
                    c.warning = True
                    c.message = f"Ollama daemon online, but model '{target_model}' is not installed (found: {models or 'none'})."
                    c.fix_hint = f"Pull the resident model by running: 'ollama pull {target_model}'"
        except Exception as e:
            c.warning = True
            c.message = f"Ollama listening but API failed to respond: {e}"
            c.fix_hint = "Verify Ollama service health: 'ollama list'"
    else:
        c.warning = True
        c.message = "Ollama daemon not detected on 127.0.0.1:11434. (Offline deterministic fallback will be used)"
        c.fix_hint = "Start Ollama daemon with 'ollama serve' or run the launcher script 'python scripts/launch.py'"
    checks.append(c)

    # 7. Forensic Registry & Qualification Compiler
    c = DoctorCheck("Forensic Registry Integrity")
    try:
        registry = load_registry(verify_hash=True)
        c.message = f"Registry verified byte-for-byte ({len(registry)} qualification rules loaded, SHA-256 verified)"
    except Exception as e:
        c.passed = False
        c.message = f"Registry verification failed: {e}"
        c.fix_hint = "Restore 01_REGISTRY/releases/registry-v1.json or re-run compiler verification."
    checks.append(c)

    # 8. Golden Outputs Snapshot
    c = DoctorCheck("Golden Regression Corpus")
    golden_file = REPO_ROOT / "05_QA" / "golden" / "golden_outputs.json"
    if golden_file.exists() and golden_file.stat().st_size > 0:
        c.message = f"Golden outputs active at {golden_file.name} ({golden_file.stat().st_size} bytes)"
    else:
        c.passed = False
        c.message = "Golden outputs snapshot missing!"
        c.fix_hint = "Generate golden outputs with: 'python scripts/save_golden.py'"
    checks.append(c)

    return checks


def print_doctor_report(checks: list[DoctorCheck]) -> bool:
    print("=" * 76)
    print("                 HOPZERO COMMERCIAL SYSTEM DIAGNOSTIC (DOCTOR)        ")
    print("=" * 76)

    all_passed = True
    warnings = 0

    for chk in checks:
        if not chk.passed:
            status = "[FAIL]"
            all_passed = False
        elif chk.warning:
            status = "[WARN]"
            warnings += 1
        else:
            status = "[ OK ]"

        print(f"{status} {chk.name}:")
        print(f"       {chk.message}")
        if chk.fix_hint:
            print(f"       --> FIX HINT: {chk.fix_hint}")
        print()

    print("=" * 76)
    if all_passed and warnings == 0:
        print("Verdict: ALL CHECKS PASSED. System is 100% release-ready.")
    elif all_passed:
        print(f"Verdict: PASSED WITH {warnings} WARNING(S). System is operational.")
    else:
        print("Verdict: ONE OR MORE CHECKS FAILED. Please follow the FIX HINTS above.")
    print("=" * 76)
    return all_passed


if __name__ == "__main__":
    checks = run_diagnostics()
    success = print_doctor_report(checks)
    sys.exit(0 if success else 1)
