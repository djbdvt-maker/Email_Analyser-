"""
03_BACKEND/tests/test_paths_and_clock.py
Tests for cross-platform OS app data directories and injectable UTC clock.
"""
import os
from pathlib import Path
from datetime import datetime, timezone
from hopzero.core.paths import (
    get_app_data_root,
    get_artifacts_dir,
    get_default_sqlite_db_path,
    get_logs_dir,
)
from hopzero.core.clock import (
    get_utc_now,
    get_utc_iso,
    set_clock_override,
    reset_clock_override,
    frozen_clock,
)


def test_paths_types_and_creation(tmp_path):
    os.environ["HOPZERO_DATA_DIR"] = str(tmp_path)
    try:
        app_data = get_app_data_root()
        assert isinstance(app_data, Path)
        assert app_data.exists()
        assert app_data == tmp_path

        artifacts = get_artifacts_dir()
        assert isinstance(artifacts, Path)
        assert artifacts.exists()
        assert artifacts.parent == tmp_path

        db_path = get_default_sqlite_db_path()
        assert isinstance(db_path, Path)
        assert db_path.name == "hopzero.db"

        logs_dir = get_logs_dir()
        assert isinstance(logs_dir, Path)
        assert logs_dir.exists()
    finally:
        os.environ.pop("HOPZERO_DATA_DIR", None)


def test_clock_utc_timezone():
    now = get_utc_now()
    assert isinstance(now, datetime)
    assert now.tzinfo is not None
    assert now.tzinfo == timezone.utc

    iso = get_utc_iso()
    assert isinstance(iso, str)
    assert iso.endswith("Z")


def test_clock_injectable_override():
    fake_time = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    with frozen_clock(fake_time):
        assert get_utc_now() == fake_time
        assert get_utc_iso() == "2026-01-15T12:00:00Z"

    # Reset verifies live time restored
    live_time = get_utc_now()
    assert live_time.year >= 2026
