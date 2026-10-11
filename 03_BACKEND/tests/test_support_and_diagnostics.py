"""
03_BACKEND/tests/test_support_and_diagnostics.py
Tests for sanitized support diagnostics, redaction engine, zero-telemetry enforcement, and diagnostics endpoints.
"""
import zipfile
from pathlib import Path
from scripts.diagnostics import redact_text, collect_sanitized_diagnostics, export_diagnostics_archive


def test_redact_text_sanitizes_pii_and_secrets():
    raw_sample = (
        "User analyst@corp.example.com logged in from 198.51.100.42 with token "
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSecret "
        "and apiKey: SuperSecret12345!"
    )
    clean = redact_text(raw_sample)

    assert "analyst@corp.example.com" not in clean
    assert "[REDACTED_EMAIL]" in clean

    assert "198.51.100.42" not in clean
    assert "[REDACTED_IP]" in clean

    assert "eyJhbGci" not in clean
    assert "[REDACTED_JWT_TOKEN]" in clean

    assert "SuperSecret12345!" not in clean
    assert "[REDACTED_CREDENTIAL]" in clean


def test_collect_sanitized_diagnostics():
    data = collect_sanitized_diagnostics()
    assert data["version"] == "4.2.0"
    assert "telemetry" in data["settings"]
    assert "DISABLED" in data["settings"]["telemetry"]
    assert "doctor" in data
    assert "hardware" in data


def test_export_diagnostics_archive(tmp_path):
    out_zip = tmp_path / "test_diag.zip"
    res_path = export_diagnostics_archive(out_zip)
    assert res_path.exists()
    assert zipfile.is_zipfile(res_path)

    with zipfile.ZipFile(res_path, "r") as zf:
        names = zf.namelist()
        assert "diagnostics_report.json" in names


def test_system_diagnostics_endpoints(client):
    res = client.get("/api/v1/system/diagnostics")
    assert res.status_code == 200
    data = res.json()
    assert data["version"] == "4.2.0"
    assert "DISABLED" in data["settings"]["telemetry"]

    res_export = client.get("/api/v1/system/diagnostics/export")
    assert res_export.status_code == 200
    assert res_export.headers["content-type"] == "application/zip"
