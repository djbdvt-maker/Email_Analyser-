#!/usr/bin/env python3
"""
scripts/verify_update.py
Cryptographic update verifier.
Verifies digital signatures and SHA-256 file hashes before an update is applied.
"""
import sys
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from hopzero.core.signatures import (
    verify_manifest_signature,
    verify_directory_against_manifest,
)


def verify_target(target_dir: Path) -> bool:
    manifest_file = target_dir / "release_manifest.json"
    sig_file = target_dir / "release_manifest.sig"

    if not manifest_file.exists() or not sig_file.exists():
        print(f"[FAIL] Missing release_manifest.json or release_manifest.sig in {target_dir}")
        return False

    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    signature = sig_file.read_text(encoding="utf-8").strip()

    print(f"[*] Validating cryptographic signature for {len(manifest)} release files...")
    if not verify_manifest_signature(manifest, signature):
        print("[FAIL] Digital signature is INVALID or corrupted!")
        return False

    print("    [OK] Signature verified successfully.")
    print("[*] Validating file content checksums...")
    is_valid, errors = verify_directory_against_manifest(target_dir, manifest)
    if not is_valid:
        print("[FAIL] Checksum verification failed:")
        for err in errors:
            print(f"  - {err}")
        return False

    print("    [OK] All release files match their signed checksums byte-for-byte.")
    print("[SUCCESS] Update package is authentic and verified.")
    return True


import tempfile
import zipfile


if __name__ == "__main__":
    target = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else REPO_ROOT
    if target.is_file() and target.suffix.lower() == ".zip":
        print(f"[*] Extracting archive {target.name} to temporary sandbox for verification...")
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with zipfile.ZipFile(target, "r") as zf:
                zf.extractall(tmp_path)
            success = verify_target(tmp_path)
    else:
        success = verify_target(target)
    sys.exit(0 if success else 1)
