#!/usr/bin/env python3
"""
scripts/package_release.py
HopZero Commercial Release Packager.
- Compiles frontend production bundle (Vite + TypeScript).
- Assembles clean, standalone release directory tree.
- Generates cryptographic SHA-256 checksum manifest and HMAC signature.
- Produces signed release archive with verified integrity.
"""
import os
import sys
import shutil
import json
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "01_REGISTRY"))
sys.path.insert(0, str(REPO_ROOT / "02_FORENSICS"))
sys.path.insert(0, str(REPO_ROOT / "03_BACKEND"))

from hopzero.core.signatures import (
    compute_file_sha256,
    compute_manifest_checksums,
    sign_manifest,
    verify_manifest_signature,
    verify_directory_against_manifest,
)


def build_frontend():
    print("[*] Building frontend production bundle (04_FRONTEND)...")
    npm_bin = shutil.which("npm.cmd") if sys.platform == "win32" else shutil.which("npm")
    if not npm_bin:
        raise RuntimeError("npm is required to compile production frontend bundle.")
    subprocess = __import__("subprocess")
    subprocess.run([npm_bin, "run", "build"], cwd=str(REPO_ROOT / "04_FRONTEND"), check=True)
    dist_dir = REPO_ROOT / "04_FRONTEND" / "dist"
    if not (dist_dir / "index.html").exists():
        raise RuntimeError(f"Frontend build failed to produce {dist_dir / 'index.html'}")
    print("    [OK] Frontend compiled successfully.")


def package_release(version: str = "4.2.0") -> Path:
    build_frontend()

    release_dir = REPO_ROOT / "dist" / "releases"
    stage_dir = release_dir / f"hopzero-{version}"
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Assembling release payload in {stage_dir}...")

    # Folders to bundle
    include_dirs = [
        "01_REGISTRY",
        "02_FORENSICS",
        "03_BACKEND",
        "07_EXTENSION",
        "hopzero",
        "scripts",
        "docs",
    ]
    for d in include_dirs:
        src = REPO_ROOT / d
        dst = stage_dir / d
        shutil.copytree(
            src, dst,
            ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", ".venv", "storage", "*.db", "*.bak")
        )

    # Copy prebuilt frontend dist
    ui_src = REPO_ROOT / "04_FRONTEND" / "dist"
    ui_dst = stage_dir / "04_FRONTEND" / "dist"
    shutil.copytree(ui_src, ui_dst)

    # Copy root configuration and launchers
    include_files = [
        "pyproject.toml",
        ".python-version",
        "requirements.lock",
        ".env.example",
        ".gitattributes",
        "README.md",
        "hopzero.bat",
        "hopzero.ps1",
        "hopzero.sh",
    ]
    for f in include_files:
        src = REPO_ROOT / f
        if src.exists():
            shutil.copy2(src, stage_dir / f)

    # Generate cryptographic release manifest
    print("[*] Generating SHA-256 release checksum manifest...")
    checksums = compute_manifest_checksums(stage_dir)
    manifest_path = stage_dir / "release_manifest.json"
    manifest_path.write_text(json.dumps(checksums, indent=2, sort_keys=True), encoding="utf-8")

    # Generate HMAC signature
    print("[*] Cryptographically signing release manifest...")
    signature = sign_manifest(checksums)
    sig_path = stage_dir / "release_manifest.sig"
    sig_path.write_text(signature, encoding="utf-8")

    # Verify signature before packaging
    assert verify_manifest_signature(checksums, signature), "Signature validation check failed!"
    is_valid, errors = verify_directory_against_manifest(stage_dir, checksums)
    assert is_valid, f"Self-verification failed: {errors}"
    print(f"    [OK] Release manifest signed ({len(checksums)} files verified).")

    # Create zip archive
    zip_path = release_dir / f"hopzero-{version}-standalone.zip"
    if zip_path.exists():
        zip_path.unlink()

    print(f"[*] Creating compressed release archive: {zip_path.name}...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in stage_dir.rglob("*"):
            if file.is_file():
                zf.write(file, arcname=file.relative_to(stage_dir).as_posix())

    # Generate archive SHA-256 checksum
    archive_sha = compute_file_sha256(zip_path)
    sha_file = release_dir / f"{zip_path.name}.sha256"
    sha_file.write_text(f"{archive_sha} *{zip_path.name}\n", encoding="utf-8")

    print(f"\n[OK] Release package created successfully!")
    print(f"     Archive: {zip_path} ({zip_path.stat().st_size / (1024**2):.2f} MB)")
    print(f"     SHA-256: {archive_sha}")
    print(f"     Checksum file: {sha_file}")
    return zip_path


if __name__ == "__main__":
    package_release()
