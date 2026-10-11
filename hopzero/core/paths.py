"""
hopzero.core.paths
Cross-platform OS-native application directory resolver using pathlib.
Ensures zero hardcoded absolute paths, adheres to OS conventions for
data and logs, and supports portable/override modes via environment variables.
"""
import os
import sys
from pathlib import Path


def get_app_data_root() -> Path:
    """
    Returns the root application data directory according to OS standard conventions.
    Override precedence:
      1. HOPZERO_DATA_DIR environment variable
      2. Windows: %LOCALAPPDATA%\\HopZero (or %APPDATA%\\HopZero)
      3. macOS: ~/Library/Application Support/HopZero
      4. Linux: $XDG_DATA_HOME/hopzero or ~/.local/share/hopzero
    """
    custom_dir = os.environ.get("HOPZERO_DATA_DIR")
    if custom_dir:
        p = Path(custom_dir).resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    # Development or portable flag
    if os.environ.get("HOPZERO_PORTABLE", "0").lower() in ("1", "true", "yes"):
        repo_root = Path(__file__).resolve().parent.parent.parent
        p = repo_root / "storage"
        p.mkdir(parents=True, exist_ok=True)
        return p

    home = Path.home()
    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            base = Path(local_app_data)
        else:
            app_data = os.environ.get("APPDATA")
            base = Path(app_data) if app_data else home / "AppData" / "Local"
        p = base / "HopZero"
    elif sys.platform == "darwin":
        p = home / "Library" / "Application Support" / "HopZero"
    else:
        xdg_data = os.environ.get("XDG_DATA_HOME")
        base = Path(xdg_data) if xdg_data else home / ".local" / "share"
        p = base / "hopzero"

    p.mkdir(parents=True, exist_ok=True)
    return p


def get_artifacts_dir() -> Path:
    """Returns directory path where forensic artifacts are stored."""
    override = os.environ.get("ARTIFACT_STORAGE_ROOT")
    if override:
        p = Path(override).resolve()
    else:
        p = get_app_data_root() / "artifacts"
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_default_sqlite_db_path() -> Path:
    """Returns default path for local SQLite database."""
    return get_app_data_root() / "hopzero.db"


def get_logs_dir() -> Path:
    """Returns default path for application log files."""
    p = get_app_data_root() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p
