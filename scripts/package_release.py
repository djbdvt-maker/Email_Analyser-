#!/usr/bin/env python3
"""
scripts/package_release.py
HopZero Commercial Release Packager (F3 Step 4).
- Compiles frontend production bundle (Vite + TypeScript).
- Assembles clean, standalone release directory tree strictly from tracked/vetted files.
- Strictly excludes untracked files, virtualenvs, secrets, databases, and bulk corpora.
- Generates cryptographic SHA-256 checksum manifest and Ed25519 asymmetric signature.
- Produces signed release archive with verified integrity.
"""
import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Set

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "01_REGISTRY"))
sys.path.insert(0, str(REPO_ROOT / "02_FORENSICS"))
sys.path.insert(0, str(REPO_ROOT / "03_BACKEND"))

import hopzero
from hopzero.core.signatures import (
    compute_file_sha256,
    compute_manifest_checksums,
    sign_manifest,
    verify_directory_against_manifest,
    verify_manifest_signature,
)

FORBIDDEN_NAME_PATTERNS = {
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    "test.db",
    "hopzero.db",
    "storage.db",
}

FORBIDDEN_DIR_PREFIXES = (
    "07_TEST_DATA/test_emails",
    "08_FINETUNING",
    "tools",
    ".venv",
    ".git",
    ".github",
    ".pytest_cache",
    "__pycache__",
    "storage",
    "dist",
)


def get_git_tracked_files() -> Optional[List[str]]:
    """Retrieves list of git-tracked files if git is available."""
    try:
        res = subprocess.run(
            ["git", "ls-files"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        return [line.strip().replace("\\", "/") for line in res.stdout.splitlines() if line.strip()]
    except Exception:
        return None


def should_include_path(rel_posix: str) -> bool:
    """Evaluates whether a relative path is allowed in the distribution payload."""
    parts = rel_posix.split("/")
    filename = parts[-1]

    # Strictly disallow forbidden files
    if filename in FORBIDDEN_NAME_PATTERNS:
        return False
    if filename.endswith(".key") or filename.endswith(".pem") or filename.endswith(".patch"):
        return False
    if filename.endswith(".db") or filename.endswith(".sqlite"):
        return False

    # Strictly disallow forbidden folders
    for prefix in FORBIDDEN_DIR_PREFIXES:
        if rel_posix == prefix or rel_posix.startswith(prefix + "/"):
            return False

    # Include specific top-level modules and assets
    allowed_top_dirs = {
        "01_REGISTRY",
        "02_FORENSICS",
        "03_BACKEND",
        "07_EXTENSION",
        "config",
        "docs",
        "hopzero",
        "scripts",
    }
    top_dir = parts[0]
    if top_dir in allowed_top_dirs:
        # Extra hygiene checks for subfolders
        if any(p in {"__pycache__", ".pytest_cache", "node_modules", ".venv", "storage"} for p in parts):
            return False
        return True

    # Allowed root files
    allowed_root_files = {
        "pyproject.toml",
        ".python-version",
        "requirements.lock",
        ".env.example",
        ".gitattributes",
        ".editorconfig",
        "README.md",
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CHANGELOG.md",
        "hopzero.bat",
        "hopzero.ps1",
        "hopzero.sh",
    }
    if len(parts) == 1 and filename in allowed_root_files:
        return True

    return False


def build_frontend():
    print("[*] Building frontend production bundle (04_FRONTEND)...")
    npm_bin = shutil.which("npm.cmd") if sys.platform == "win32" else shutil.which("npm")
    if not npm_bin:
        raise RuntimeError("npm is required to compile production frontend bundle.")
    subprocess.run([npm_bin, "run", "build"], cwd=str(REPO_ROOT / "04_FRONTEND"), check=True)
    dist_dir = REPO_ROOT / "04_FRONTEND" / "dist"
    if not (dist_dir / "index.html").exists():
        raise RuntimeError(f"Frontend build failed to produce {dist_dir / 'index.html'}")
    print("    [OK] Frontend compiled successfully.")


def safe_rmtree(path: Path):
    """Safely removes directory tree on Windows handling read-only attributes and transient locks."""
    import stat
    import time
    def _on_error(func, p, _):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            time.sleep(0.05)
            try:
                func(p)
            except Exception:
                pass
    if path.exists():
        shutil.rmtree(path, onerror=_on_error)


def package_release(
    version: Optional[str] = None,
    key_file: Optional[Path] = None,
    skip_frontend_build: bool = False,
    unsigned: bool = False,
) -> Path:
    release_version = version or hopzero.__version__

    if not skip_frontend_build:
        build_frontend()
    else:
        dist_dir = REPO_ROOT / "04_FRONTEND" / "dist"
        if not (dist_dir / "index.html").exists():
            print("[*] Frontend dist missing; compiling bundle...")
            build_frontend()

    release_dir = REPO_ROOT / "dist" / "releases"
    stage_dir = release_dir / f"hopzero-{release_version}"
    safe_rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Assembling release payload in {stage_dir}...")

    # Assemble tracked files
    tracked = get_git_tracked_files()
    if tracked is not None:
        print(f"    Scanning {len(tracked)} git-tracked files for inclusion...")
        files_to_copy = [f for f in tracked if should_include_path(f)]
    else:
        print("    Git not detected; performing filesystem walk...")
        files_to_copy = []
        for p in REPO_ROOT.rglob("*"):
            if p.is_file():
                rel = p.relative_to(REPO_ROOT).as_posix()
                if should_include_path(rel):
                    files_to_copy.append(rel)

    for rel in files_to_copy:
        src = REPO_ROOT / rel
        if not src.is_file():
            continue
        dst = stage_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    # Copy prebuilt frontend dist
    ui_src = REPO_ROOT / "04_FRONTEND" / "dist"
    ui_dst = stage_dir / "04_FRONTEND" / "dist"
    if ui_src.exists():
        shutil.copytree(ui_src, ui_dst)

    # Security Sanity Check on assembled stage_dir
    print("[*] Running security packaging sanity scan on staged files...")
    for staged_file in stage_dir.rglob("*"):
        if staged_file.is_file():
            name = staged_file.name
            rel = staged_file.relative_to(stage_dir).as_posix()
            if name in FORBIDDEN_NAME_PATTERNS or name.endswith(".db") or name.endswith(".sqlite"):
                raise RuntimeError(f"SECURITY VIOLATION: Staged release contains forbidden file {rel}")
            if "07_TEST_DATA/test_emails" in rel or "08_FINETUNING" in rel or rel.startswith("tools/"):
                raise RuntimeError(f"SECURITY VIOLATION: Staged release contains forbidden directory content {rel}")

    # Generate SHA-256 release checksum manifest
    print("[*] Generating SHA-256 release checksum manifest...")
    checksums = compute_manifest_checksums(stage_dir)
    manifest_path = stage_dir / "release_manifest.json"
    manifest_path.write_text(json.dumps(checksums, indent=2, sort_keys=True), encoding="utf-8")

    # Cryptographically sign release manifest with Ed25519
    sig_path = stage_dir / "release_manifest.sig"
    private_key_data = None
    if key_file and Path(key_file).exists():
        private_key_data = Path(key_file).read_bytes()
    elif os.getenv("HOPZERO_RELEASE_PRIVATE_KEY"):
        private_key_data = os.getenv("HOPZERO_RELEASE_PRIVATE_KEY")

    if private_key_data:
        print("[*] Cryptographically signing release manifest with Ed25519...")
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from hopzero.core.signatures import _coerce_private_key
        priv_obj = _coerce_private_key(private_key_data)
        pub_raw = priv_obj.public_key().public_bytes_raw()

        signature = sign_manifest(checksums, private_key=priv_obj)
        sig_path.write_text(signature, encoding="utf-8")

        # Verify signature before packaging
        assert verify_manifest_signature(checksums, signature, trusted_public_keys=[pub_raw]), (
            "Release signature self-verification check failed!"
        )
        is_valid, errors = verify_directory_against_manifest(stage_dir, checksums)
        assert is_valid, f"Staged release self-verification failed: {errors}"
        print(f"    [OK] Release manifest signed ({len(checksums)} files verified).")
    else:
        if unsigned:
            print("    [WARN] Release manifest generated WITHOUT Ed25519 signature (--unsigned flag set).")
        else:
            print("    [NOTICE] No release private key found. Manifest saved unsigned.")
            print("             Maintainers can sign offline via: python tools/sign_release.py sign -d "
                  f"dist/releases/hopzero-{release_version} -k <private_key>")

    # Create zip archive
    zip_path = release_dir / f"hopzero-{release_version}-standalone.zip"
    if zip_path.exists():
        zip_path.unlink()

    print(f"[*] Creating compressed release archive: {zip_path.name}...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in sorted(stage_dir.rglob("*")):
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


def main():
    parser = argparse.ArgumentParser(description="HopZero Commercial Release Packager")
    parser.add_argument("--version", "-v", default=hopzero.__version__, help="Release version string")
    parser.add_argument("--key-file", "-k", type=Path, help="Path to offline Ed25519 release private key")
    parser.add_argument("--skip-frontend-build", action="store_true", help="Skip npm run build step")
    parser.add_argument("--unsigned", action="store_true", help="Create unsigned release without key prompt")

    args = parser.parse_args()
    package_release(
        version=args.version,
        key_file=args.key_file,
        skip_frontend_build=args.skip_frontend_build,
        unsigned=args.unsigned,
    )


if __name__ == "__main__":
    main()
