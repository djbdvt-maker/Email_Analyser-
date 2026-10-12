"""
03_BACKEND/tests/test_claims_and_counts.py
Tests for F7 & F12:
- scripts/check_claims.py passes clean and fails on planted bad phrase.
- Doctor output, API endpoint, and registry counts match.
"""
import subprocess
import sys
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from hopzero.core.registry import load_registry
from scripts.doctor import run_diagnostics

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_check_claims_clean():
    res = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "check_claims.py")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"check_claims failed: {res.stdout}\n{res.stderr}"
    assert "PASS" in res.stdout


def test_check_claims_fails_on_planted_forbidden_phrase(tmp_path):
    test_file = REPO_ROOT / "docs" / "scratch_planted_claim_test.md"
    try:
        test_file.write_text("This system promises 100% on-premises determinism without fail.", encoding="utf-8")
        # Run check_claims
        from scripts.check_claims import check_claims_in_files
        violations = check_claims_in_files()
        assert any("scratch_planted_claim_test.md" in v and "100% on-premises determinism" in v for v in violations)
    finally:
        if test_file.exists():
            test_file.unlink()


def test_registry_counts_match_across_doctor_api_and_loader():
    """F12: Verifies that doctor check, API endpoint, and registry loader agree dynamically."""
    reg = load_registry(verify_hash=True)
    q_count = len(reg["qualifications"])
    fl_count = len(reg["floors"])
    sb_count = len(reg["scoring_buckets"])

    assert q_count == 43
    assert fl_count == 6
    assert sb_count == 9

    # 1. Verify doctor output message
    checks = run_diagnostics(verbose=False)
    reg_check = next((c for c in checks if c.name == "Forensic Registry Integrity"), None)
    assert reg_check is not None
    assert reg_check.passed is True
    assert f"{q_count} qualifications" in reg_check.message
    assert f"{fl_count} floors" in reg_check.message
    assert f"{sb_count} scoring buckets" in reg_check.message

    # 2. Verify API endpoint /system/registry
    client = TestClient(app)
    resp = client.get("/api/v1/system/registry")
    assert resp.status_code == 200
    data = resp.json()
    assert data["qualifications_count"] == q_count
    assert data["floors_count"] == fl_count
    assert data["scoring_buckets_count"] == sb_count
    assert data["version"] == "v1"
