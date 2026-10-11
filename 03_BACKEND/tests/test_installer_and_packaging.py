"""
03_BACKEND/tests/test_installer_and_packaging.py
Tests for installer prerequisites, atomic rollback transaction, and cryptographic signature verification.
"""
from pathlib import Path
from hopzero.core.signatures import (
    compute_manifest_checksums,
    sign_manifest,
    verify_manifest_signature,
    verify_directory_against_manifest,
    compute_file_sha256,
)
from scripts.install import InstallTransaction, check_prerequisites


def test_signature_signing_and_verification(tmp_path):
    f1 = tmp_path / "app.py"
    f1.write_text("print('hello')", encoding="utf-8")
    f2 = tmp_path / "config.json"
    f2.write_text('{"v": 1}', encoding="utf-8")

    manifest = compute_manifest_checksums(tmp_path)
    assert len(manifest) == 2
    assert "app.py" in manifest
    assert "config.json" in manifest

    # Sign manifest
    sig = sign_manifest(manifest, secret_key="test-key")
    assert isinstance(sig, str)
    assert len(sig) == 64  # SHA-256 hex string

    # Verify signature
    assert verify_manifest_signature(manifest, sig, secret_key="test-key")
    assert not verify_manifest_signature(manifest, sig, secret_key="wrong-key")

    # Directory verification
    is_valid, errors = verify_directory_against_manifest(tmp_path, manifest)
    assert is_valid
    assert len(errors) == 0

    # Tampering detection: modify f1
    f1.write_text("print('tampered')", encoding="utf-8")
    is_valid, errors = verify_directory_against_manifest(tmp_path, manifest)
    assert not is_valid
    assert any("Checksum mismatch" in e for e in errors)


def test_install_transaction_rollback(tmp_path):
    tx = InstallTransaction()
    test_file = tmp_path / "created_by_installer.txt"
    test_file.write_text("payload", encoding="utf-8")
    tx.track(test_file)

    assert test_file.exists()
    # Trigger rollback
    tx.rollback()
    assert not test_file.exists()


def test_install_transaction_commit(tmp_path):
    tx = InstallTransaction()
    test_file = tmp_path / "committed_file.txt"
    test_file.write_text("payload", encoding="utf-8")
    tx.track(test_file)

    tx.commit()
    # Rollback after commit should do nothing
    tx.rollback()
    assert test_file.exists()


def test_check_prerequisites():
    prereqs = check_prerequisites(offline=True)
    assert "ok" in prereqs
    assert isinstance(prereqs["reasons"], list)
