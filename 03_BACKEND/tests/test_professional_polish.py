"""
Unit tests for Section 9: Professional Polish.
Verifies README structure, documentation index, frontend production assets,
and FirstRunWizard accessibility.
"""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_readme_polish_and_completeness():
    readme_file = REPO_ROOT / "README.md"
    assert readme_file.is_file(), "README.md must exist in repo root"

    content = readme_file.read_text(encoding="utf-8")
    assert "Quickstart per OS" in content
    assert "hopzero.bat" in content
    assert "System Architecture" in content
    assert "5-Level Progressive Disclosure" in content
    assert "Support Matrix" in content
    assert "Known Limitations & Operational Bounds" in content
    assert "Apache License, Version 2.0" in content
    assert "doctor" in content


def test_docs_index_exists_and_references_core_specs():
    index_file = REPO_ROOT / "docs" / "INDEX.md"
    assert index_file.is_file(), "docs/INDEX.md must exist"

    content = index_file.read_text(encoding="utf-8")
    assert "ARCHITECTURE_AND_SPECIFICATION.md" in content
    assert "DECISIONS.md" in content
    assert "THREAT_MODEL.md" in content
    assert "TERMS_OF_SERVICE.md" in content
    assert "TELEMETRY.md" in content


def test_frontend_distribution_bundle_built():
    dist_dir = REPO_ROOT / "04_FRONTEND" / "dist"
    index_html = dist_dir / "index.html"
    assert index_html.is_file(), "04_FRONTEND/dist/index.html must exist from build"


def test_first_run_wizard_component():
    wizard_file = REPO_ROOT / "04_FRONTEND" / "src" / "components" / "FirstRunWizard.tsx"
    assert wizard_file.is_file(), "FirstRunWizard.tsx must exist"

    content = wizard_file.read_text(encoding="utf-8")
    assert 'role="dialog"' in content
    assert 'aria-modal="true"' in content
    assert "hopzero_first_run_completed" in content
    assert "5 Levels of Progressive Disclosure" in content
