"""
hopzero.core.signatures
Cryptographic release artifact hashing, signature generation, and verification.
Provides tamper-detection and verified auto-updates for HopZero commercial distributions.
"""
import hmac
import hashlib
import json
from pathlib import Path
from typing import Dict, Tuple, List, Optional

# Default public release verification key (overridable via HOPZERO_RELEASE_KEY)
DEFAULT_RELEASE_KEY = "hopzero-v4-official-release-signing-key-2026"


def compute_file_sha256(path: Path) -> str:
    """Computes SHA-256 hex digest of a file in streaming chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def compute_manifest_checksums(root_dir: Path, exclude_patterns: Optional[List[str]] = None) -> Dict[str, str]:
    """
    Computes relative-path SHA-256 checksums for all files within a directory tree.
    """
    excludes = set(exclude_patterns or [
        "__pycache__", ".git", ".pytest_cache", "node_modules", ".venv",
        "release_manifest.json", "release_manifest.sig", "*.bak", "*.tmp"
    ])
    checksums = {}

    for path in sorted(root_dir.rglob("*")):
        if path.is_file():
            # Check exclusions
            parts = set(path.parts)
            if any(exc in parts or path.match(exc) for exc in excludes):
                continue
            rel_path = path.relative_to(root_dir).as_posix()
            checksums[rel_path] = compute_file_sha256(path)

    return checksums


def sign_manifest(checksums: Dict[str, str], secret_key: str = DEFAULT_RELEASE_KEY) -> str:
    """Computes HMAC-SHA256 signature over canonically serialized manifest."""
    canonical_data = json.dumps(checksums, sort_keys=True).encode("utf-8")
    sig = hmac.new(secret_key.encode("utf-8"), canonical_data, hashlib.sha256).hexdigest()
    return sig


def verify_manifest_signature(
    checksums: Dict[str, str], signature: str, secret_key: str = DEFAULT_RELEASE_KEY
) -> bool:
    """Validates HMAC-SHA256 signature using constant-time comparison."""
    expected_sig = sign_manifest(checksums, secret_key)
    return hmac.compare_digest(expected_sig, signature)


def verify_directory_against_manifest(
    root_dir: Path, manifest: Dict[str, str]
) -> Tuple[bool, List[str]]:
    """
    Verifies that all files in manifest exist and match their expected SHA-256 digests.
    Returns (True, []) if 100% intact, or (False, [mismatch_errors]) on corruption/tampering.
    """
    errors = []
    for rel_path, expected_hash in manifest.items():
        target = root_dir / rel_path
        if not target.exists():
            errors.append(f"Missing file: {rel_path}")
            continue
        actual_hash = compute_file_sha256(target)
        if actual_hash != expected_hash:
            errors.append(f"Checksum mismatch on {rel_path}: expected {expected_hash}, got {actual_hash}")

    return len(errors) == 0, errors
