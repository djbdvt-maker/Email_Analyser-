"""
03_BACKEND/tests/test_version_single_source.py
Tests for F14: Single source of truth for version across package metadata,
API application instance, tool manifest, and CHANGELOG.md head.
"""
import re
from pathlib import Path
from hopzero import __version__ as EXPECTED_VERSION
from app.main import app
from app.api.v1.routes_tool import TOOL_MANIFEST, SYSTEM_VERSION_INFO

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_package_metadata_version_matches():
    pyproject_text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'version\s*=\s*"([^"]+)"', pyproject_text)
    assert m is not None, "Version not found in pyproject.toml"
    assert m.group(1) == EXPECTED_VERSION


def test_changelog_head_version_matches():
    changelog_text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    m = re.search(r'##\s*\[([^\]]+)\]', changelog_text)
    assert m is not None, "First release header not found in CHANGELOG.md"
    assert m.group(1) == EXPECTED_VERSION


def test_fastapi_app_version_matches():
    assert app.version == EXPECTED_VERSION


def test_tool_manifest_and_system_info_version_matches():
    assert TOOL_MANIFEST["version"] == EXPECTED_VERSION
    assert SYSTEM_VERSION_INFO["backend_version"] == EXPECTED_VERSION
