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
    from cryptography.hazmat.primitives.asymmetric import ed25519
    test_priv = ed25519.Ed25519PrivateKey.generate()
    test_pub_bytes = test_priv.public_key().public_bytes_raw()
    wrong_pub_bytes = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()

    f1 = tmp_path / "app.py"
    f1.write_text("print('hello')", encoding="utf-8")
    f2 = tmp_path / "config.json"
    f2.write_text('{"v": 1}', encoding="utf-8")

    manifest = compute_manifest_checksums(tmp_path)
    assert len(manifest) == 2
    assert "app.py" in manifest
    assert "config.json" in manifest

    # Sign manifest with Ed25519 private key
    sig = sign_manifest(manifest, private_key=test_priv)
    assert isinstance(sig, str)

    # Verify signature
    assert verify_manifest_signature(manifest, sig, trusted_public_keys=[test_pub_bytes])
    assert not verify_manifest_signature(manifest, sig, trusted_public_keys=[wrong_pub_bytes])

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


def test_package_release_filtering_rules():
    from scripts.package_release import should_include_path

    # Strictly excluded paths
    assert not should_include_path(".env")
    assert not should_include_path(".env.local")
    assert not should_include_path("03_BACKEND/.env")
    assert not should_include_path("test.db")
    assert not should_include_path("03_BACKEND/storage/hopzero.db")
    assert not should_include_path("07_TEST_DATA/test_emails/20030228_easy_ham/0001.txt")
    assert not should_include_path("08_FINETUNING/train.py")
    assert not should_include_path("tools/sign_release.py")
    assert not should_include_path(".venv/Scripts/python.exe")
    assert not should_include_path("03_BACKEND/__pycache__/main.cpython-312.pyc")
    assert not should_include_path("diff.patch")
    assert not should_include_path("release_private.key")

    # Strictly included paths
    assert should_include_path("pyproject.toml")
    assert should_include_path("requirements.lock")
    assert should_include_path(".env.example")
    assert should_include_path("README.md")
    assert should_include_path("01_REGISTRY/releases/registry-v1.json")
    assert should_include_path("02_FORENSICS/hopzero_forensics/parser.py")
    assert should_include_path("03_BACKEND/app/main.py")
    assert should_include_path("hopzero/core/licensing.py")
    assert should_include_path("docs/TEST_DATA.md")

