"""
Tests for Extracted Shared `hopzero-core` Package (HZ5).
========================================================
Verifies:
1. Deterministic hashing utilities (compute_sha256, canonical_json_hash, compute_file_sha256).
2. Shared domain models and contracts (SignalState, CanonicalEmail, Fact, FindingCandidate).
3. Cross-tool NormalizedEntity and AnalysisRunConfig primitives.
4. Qualification registry loader from hopzero.core.registry with cryptographic verification.
5. 100% backwards-compatibility of hopzero_forensics.interfaces re-exports.
"""
import tempfile
from pathlib import Path
import pytest

from hopzero.core import (
    compute_sha256,
    compute_file_sha256,
    canonical_json_hash,
    SignalState,
    CanonicalEmail,
    Fact,
    FindingCandidate,
    NormalizedEntity,
    AnalysisRunConfig,
    load_registry,
    get_qualification,
    get_floors,
    get_scoring_buckets,
    STRENGTH_ORDER,
)
import hopzero_forensics.interfaces as forensics_interfaces


def test_hashing_utilities():
    """Verifies that hashing functions produce canonical digests."""
    # String and bytes match
    h1 = compute_sha256("test-payload")
    h2 = compute_sha256(b"test-payload")
    assert h1 == h2
    assert len(h1) == 64

    # Canonical JSON hash is key-order independent
    d1 = {"z": 100, "a": "apple", "m": [1, 2, 3]}
    d2 = {"a": "apple", "m": [1, 2, 3], "z": 100}
    assert canonical_json_hash(d1) == canonical_json_hash(d2)

    # File hashing
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
        f.write("temporary content for sha256 file hashing verification")
        temp_path = f.name
    try:
        file_hash = compute_file_sha256(temp_path)
        assert file_hash == compute_sha256("temporary content for sha256 file hashing verification")
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_normalized_entity_primitive():
    """Verifies NormalizedEntity contract across tool boundaries."""
    entity = NormalizedEntity(
        entity_type="domain",
        normalized_value="paypal-login-security.com",
        raw_value="  PayPal-Login-Security.COM. ",
        provenance={"source": "extracted_links", "sequence_index": 2},
    )
    assert entity.entity_type == "domain"
    assert entity.normalized_value == "paypal-login-security.com"
    assert entity.provenance["sequence_index"] == 2


def test_analysis_run_config():
    """Verifies AnalysisRunConfig defaults and reproducibility anchors."""
    config = AnalysisRunConfig()
    assert config.offline_mode is True
    assert config.timeout_seconds == 60.0
    assert config.include_body is False
    assert config.registry_version == "v1"
    assert config.llm_model == "hermes3:3b"
    assert config.llm_prompt_version == "prompt-v1"
    assert config.llm_schema_version == "proposal-v1"


def test_registry_loader_from_core():
    """Verifies loading the canonical registry snapshot via hopzero.core.registry."""
    reg = load_registry(version="v1", verify_hash=True)
    assert reg["version"] == "v1"
    assert reg["content_sha256"] == "1047f1db05dd6fe51d20e124d3e42e7d7a20e985993afddfc08759942ee2a44d"

    # Qualification lookup
    spf_entry = get_qualification("SPF_FAIL", version="v1")
    assert spf_entry is not None
    assert spf_entry.category == "Authentication"
    assert spf_entry.default_strength in STRENGTH_ORDER

    # Critical floors
    floors = get_floors(version="v1")
    assert "CF-01" in floors
    assert "CF-06" in floors

    # Buckets
    buckets = get_scoring_buckets(version="v1")
    assert "Authentication" in buckets
    assert buckets["Authentication"].point_cap == 16


def test_interfaces_backwards_compatibility():
    """Proves that hopzero_forensics.interfaces re-exports the exact same types."""
    assert forensics_interfaces.SignalState is SignalState
    assert forensics_interfaces.CanonicalEmail is CanonicalEmail
    assert forensics_interfaces.Fact is Fact
    assert forensics_interfaces.FindingCandidate is FindingCandidate
    assert forensics_interfaces.NormalizedEntity is NormalizedEntity
    assert forensics_interfaces.AnalysisRunConfig is AnalysisRunConfig
