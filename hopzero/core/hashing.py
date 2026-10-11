"""
HopZero Core - Cryptographic and Deterministic Hashing Utilities.
=================================================================
Provides canonical SHA-256 computation for bytes, text, files, and JSON payloads.
Guarantees byte-for-byte reproducibility across runs.
"""
import hashlib
import json
from pathlib import Path
from typing import Any, Union


def compute_sha256(data: Union[bytes, str]) -> str:
    """Computes the lowercase hexadecimal SHA-256 digest of bytes or UTF-8 text."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_file_sha256(filepath: Union[str, Path], chunk_size: int = 65536) -> str:
    """Computes the SHA-256 digest of a file in streaming chunks."""
    p = Path(filepath)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {filepath}")
    hasher = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def canonical_json_hash(obj: Any) -> str:
    """
    Computes a deterministic SHA-256 digest of a JSON-serializable structure.
    Uses sorted keys and compact separators to ensure identical representation.
    """
    serialized = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return compute_sha256(serialized)
