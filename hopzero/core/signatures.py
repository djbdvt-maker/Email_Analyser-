"""
hopzero.core.signatures
Cryptographic release artifact hashing, Ed25519 signature generation, and verification.
Provides tamper-detection and verified distribution integrity for HopZero.
Verification only requires the embedded public key; signing requires offline maintainer private key.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

# Embedded official release signing public keys
OFFICIAL_RELEASE_PUBLIC_KEYS = [
    # Master Official Release Authority Public Key (v1)
    bytes.fromhex("6dda09936d5041561ce64a97360181266dea6000093addf47e1c58db60109084"),
]


def get_trusted_release_keys() -> List[bytes]:
    """Returns the list of trusted Ed25519 public keys for release manifest verification."""
    keys = list(OFFICIAL_RELEASE_PUBLIC_KEYS)
    custom_keys_env = os.getenv("HOPZERO_TRUSTED_RELEASE_PUBLIC_KEYS")
    if custom_keys_env:
        for k in custom_keys_env.split(","):
            k = k.strip()
            if k:
                try:
                    raw = bytes.fromhex(k) if len(k) == 64 else base64.urlsafe_b64decode(k + "=" * (-len(k) % 4))
                    if len(raw) == 32:
                        keys.append(raw)
                except Exception:
                    pass
    return keys


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
            parts = set(path.parts)
            if any(exc in parts or path.match(exc) for exc in excludes):
                continue
            rel_path = path.relative_to(root_dir).as_posix()
            checksums[rel_path] = compute_file_sha256(path)

    return checksums


def _coerce_private_key(key: Union[ed25519.Ed25519PrivateKey, bytes, str]) -> ed25519.Ed25519PrivateKey:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return key
    if isinstance(key, str):
        key = key.strip()
        raw = bytes.fromhex(key) if len(key) == 64 else base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
    if isinstance(key, (bytes, bytearray)):
        return ed25519.Ed25519PrivateKey.from_private_bytes(bytes(key))
    raise TypeError(f"Unsupported private key type: {type(key)}")


def sign_manifest(
    checksums: Dict[str, str],
    private_key: Optional[Union[ed25519.Ed25519PrivateKey, bytes, str]] = None,
) -> str:
    """
    Computes Ed25519 signature over canonically serialized manifest.
    Returns base64url-encoded signature string.
    """
    if private_key is None:
        env_key = os.getenv("HOPZERO_RELEASE_PRIVATE_KEY")
        if env_key:
            private_key = env_key
        else:
            raise ValueError(
                "An Ed25519 private key is required to sign release manifests. "
                "Maintainers should use 'tools/sign_release.py' or supply private_key."
            )

    signing_key = _coerce_private_key(private_key)
    canonical_data = json.dumps(checksums, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig_bytes = signing_key.sign(canonical_data)
    return base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")


def verify_manifest_signature(
    checksums: Dict[str, str],
    signature: str,
    trusted_public_keys: Optional[List[bytes]] = None,
) -> bool:
    """
    Validates Ed25519 signature over canonically serialized manifest using trusted public keys.
    """
    if not signature or not isinstance(signature, str):
        return False

    try:
        sig_str = signature.strip()
        pad_sig = sig_str + "=" * (-len(sig_str) % 4)
        sig_bytes = base64.urlsafe_b64decode(pad_sig.encode("ascii"))
    except Exception:
        return False

    canonical_data = json.dumps(checksums, sort_keys=True, separators=(",", ":")).encode("utf-8")
    keys_to_try = trusted_public_keys or get_trusted_release_keys()

    for pub_raw in keys_to_try:
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
            pub_key.verify(sig_bytes, canonical_data)
            return True
        except (InvalidSignature, ValueError):
            continue

    return False


def verify_directory_against_manifest(
    root_dir: Path, manifest: Dict[str, str]
) -> Tuple[bool, List[str]]:
    """
    Verifies that all files in manifest exist and match their SHA-256 hashes.
    """
    errors = []
    for rel_path, expected_hash in manifest.items():
        file_path = root_dir / rel_path
        if not file_path.is_file():
            errors.append(f"Missing release file: {rel_path}")
            continue

        actual_hash = compute_file_sha256(file_path)
        if actual_hash.lower() != expected_hash.lower():
            errors.append(
                f"Checksum mismatch for {rel_path}: expected {expected_hash}, got {actual_hash}"
            )

    return len(errors) == 0, errors
