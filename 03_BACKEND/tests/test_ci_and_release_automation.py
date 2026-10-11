"""
03_BACKEND/tests/test_ci_and_release_automation.py
Tests for CI workflows, dependabot config, network isolation test, and semantic versioning changelog.
"""
from pathlib import Path
import yaml
from scripts.test_network_isolation import run_offline_isolation_test


def test_ci_workflows_exist_and_parse(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent.parent
    workflows_dir = repo_root / ".github" / "workflows"
    assert workflows_dir.exists()

    ci_file = workflows_dir / "ci.yml"
    assert ci_file.exists()
    ci_data = yaml.safe_load(ci_file.read_text(encoding="utf-8"))
    assert "jobs" in ci_data
    # Check multi-OS matrix
    matrix = ci_data["jobs"]["matrix-test"]["strategy"]["matrix"]
    assert "windows-latest" in matrix["os"]
    assert "ubuntu-latest" in matrix["os"]
    assert "macos-latest" in matrix["os"]

    nightly = workflows_dir / "nightly-drift.yml"
    assert nightly.exists()
    nightly_data = yaml.safe_load(nightly.read_text(encoding="utf-8"))
    assert "jobs" in nightly_data

    release = workflows_dir / "release.yml"
    assert release.exists()
    rel_data = yaml.safe_load(release.read_text(encoding="utf-8"))
    assert "jobs" in rel_data


def test_dependabot_config_valid():
    repo_root = Path(__file__).resolve().parent.parent.parent
    dep_file = repo_root / ".github" / "dependabot.yml"
    assert dep_file.exists()
    data = yaml.safe_load(dep_file.read_text(encoding="utf-8"))
    assert data.get("version") == 2
    ecosystems = [u.get("package-ecosystem") for u in data.get("updates", [])]
    assert "pip" in ecosystems
    assert "npm" in ecosystems


def test_changelog_semantic_version():
    repo_root = Path(__file__).resolve().parent.parent.parent
    changelog = repo_root / "CHANGELOG.md"
    assert changelog.exists()
    text = changelog.read_text(encoding="utf-8")
    assert "[4.2.0]" in text


def test_network_isolation_test_passes():
    success = run_offline_isolation_test()
    assert success is True
