"""
03_BACKEND/tests/test_launcher_and_doctor.py
Tests for doctor diagnostics, launcher port auto-selection, and database pre-upgrade backups.
"""
import sys
from pathlib import Path
from scripts.doctor import run_diagnostics, check_port
from scripts.launch import find_free_port
from app.database import backup_database_before_upgrade
from app.config import Settings


def test_doctor_diagnostics_runs_cleanly():
    checks = run_diagnostics(verbose=False)
    assert len(checks) >= 6
    names = [c.name for c in checks]
    assert "Python Runtime" in names
    assert "Application Directories & Permissions" in names
    assert "Forensic Registry Integrity" in names
    assert "Golden Regression Corpus" in names


def test_find_free_port():
    port = find_free_port(9100)
    assert isinstance(port, int)
    assert port >= 9100
    assert not check_port("127.0.0.1", port)


def test_backup_database_before_upgrade(tmp_path, monkeypatch):
    test_db = tmp_path / "test_app.db"
    test_db.write_text("sqlite dummy data", encoding="utf-8")

    from app import database
    mock_settings = Settings(database_url=f"sqlite:///{test_db.as_posix()}")
    monkeypatch.setattr(database, "settings", mock_settings)

    backup_database_before_upgrade()

    backup_dir = tmp_path / "backups"
    assert backup_dir.exists()
    backups = list(backup_dir.glob("test_app_*.bak"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "sqlite dummy data"
