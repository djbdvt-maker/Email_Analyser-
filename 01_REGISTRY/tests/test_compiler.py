"""
Comprehensive Test Suite for HopZero Registry Compiler & Integrity Loader
========================================================================

Covers the 11 required compiler validation and integrity tests:
1. Valid registry compiles.
2. Duplicate qualification code fails.
3. Unknown floor qualification fails.
4. Invalid strength fails.
5. Invalid producer fails.
6. Invalid AI eligibility/producer combination fails.
7. Invalid scoring bucket fails.
8. Invalid floor operator fails.
9. Deterministic compilation produces identical release content.
10. Release SHA-256 matches actual release bytes.
11. Tampering with release causes loader verification failure.
"""

import os
import sys
import json
import hashlib
import copy
import yaml
import pytest

# Ensure 01_REGISTRY is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "compiler")))

from compile import (
    compile_registry,
    validate_source_specification,
    RegistryCompilationError,
    STRENGTH_ORDER,
)
from hopzero_registry.loader import load_registry, RegistryVerificationError, _REGISTRY_CACHE


@pytest.fixture
def repo_canonical_sources():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    src_dir = os.path.join(repo_root, "01_REGISTRY", "source")
    with open(os.path.join(src_dir, "qualifications.yaml"), "r", encoding="utf-8") as f:
        quals = yaml.safe_load(f)
    with open(os.path.join(src_dir, "floors.yaml"), "r", encoding="utf-8") as f:
        floors = yaml.safe_load(f)
    with open(os.path.join(src_dir, "scoring_buckets.yaml"), "r", encoding="utf-8") as f:
        buckets = yaml.safe_load(f)
    return quals, floors, buckets


def _setup_source_tree(tmp_path, quals, floors, buckets):
    src_dir = tmp_path / "source"
    src_dir.mkdir(parents=True, exist_ok=True)
    with open(src_dir / "qualifications.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump(quals, f)
    with open(src_dir / "floors.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump(floors, f)
    with open(src_dir / "scoring_buckets.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump(buckets, f)
    return str(src_dir)


# 1. Valid registry compiles
def test_1_valid_registry_compiles(tmp_path, repo_canonical_sources):
    quals, floors, buckets = repo_canonical_sources
    src_dir = _setup_source_tree(tmp_path, quals, floors, buckets)
    rel_dir = str(tmp_path / "releases")

    result = compile_registry(src_dir, rel_dir, version="test-v1")
    assert result["version"] == "test-v1"
    assert os.path.exists(result["snapshot_path"])
    assert os.path.exists(result["sha_path"])


# 2. Duplicate qualification code fails
def test_2_duplicate_qualification_code_fails(repo_canonical_sources):
    quals, floors, buckets = repo_canonical_sources
    quals_dup = copy.deepcopy(quals)
    # Duplicate first qualification code
    quals_dup.append(copy.deepcopy(quals_dup[0]))

    with pytest.raises(RegistryCompilationError, match="Duplicate qualification code"):
        validate_source_specification(quals_dup, floors, buckets)


# 3. Unknown floor qualification fails
def test_3_unknown_floor_qualification_fails(repo_canonical_sources):
    quals, floors, buckets = repo_canonical_sources
    floors_bad = copy.deepcopy(floors)
    floors_bad[0]["requirements"].append({"qualification_code": "NON_EXISTENT_QUAL", "min_strength": "Moderate"})

    with pytest.raises(RegistryCompilationError, match="references unknown qualification_code"):
        validate_source_specification(quals, floors_bad, buckets)


# 4. Invalid strength fails
def test_4_invalid_strength_fails(repo_canonical_sources):
    quals, floors, buckets = repo_canonical_sources
    # Test 4a: Invalid strength level name
    quals_bad_str = copy.deepcopy(quals)
    quals_bad_str[0]["default_strength"] = "SuperStrong"
    with pytest.raises(RegistryCompilationError, match="default_strength 'SuperStrong' is invalid"):
        validate_source_specification(quals_bad_str, floors, buckets)

    # Test 4b: Default strength exceeds maximum strength
    quals_inverted = copy.deepcopy(quals)
    quals_inverted[0]["default_strength"] = "Strong"
    quals_inverted[0]["maximum_strength"] = "Weak"
    with pytest.raises(RegistryCompilationError, match="exceeds maximum_strength"):
        validate_source_specification(quals_inverted, floors, buckets)


# 5. Invalid producer fails
def test_5_invalid_producer_fails(repo_canonical_sources):
    quals, floors, buckets = repo_canonical_sources
    quals_bad_prod = copy.deepcopy(quals)
    quals_bad_prod[0]["produced_by_allowed"] = ["external_untrusted_source"]

    with pytest.raises(RegistryCompilationError, match="unsupported producer class"):
        validate_source_specification(quals_bad_prod, floors, buckets)


# 6. Invalid AI eligibility / producer combination fails
def test_6_invalid_ai_eligibility_producer_combination_fails(repo_canonical_sources):
    quals, floors, buckets = repo_canonical_sources
    # 6a: ai_eligible is False, but producer allows ai_reasoner
    quals_incompat_1 = copy.deepcopy(quals)
    quals_incompat_1[0]["ai_eligible"] = False
    quals_incompat_1[0]["produced_by_allowed"] = ["deterministic", "ai_reasoner"]
    with pytest.raises(RegistryCompilationError, match="ai_eligible=False but permits 'ai_reasoner'"):
        validate_source_specification(quals_incompat_1, floors, buckets)

    # 6b: ai_eligible is True, but producer lacks ai_reasoner
    quals_incompat_2 = copy.deepcopy(quals)
    quals_incompat_2[0]["ai_eligible"] = True
    quals_incompat_2[0]["produced_by_allowed"] = ["deterministic"]
    with pytest.raises(RegistryCompilationError, match="'ai_reasoner' is missing from produced_by_allowed"):
        validate_source_specification(quals_incompat_2, floors, buckets)

    # 6c: ai_eligible is True, but missing validity_requirements
    quals_incompat_3 = copy.deepcopy(quals)
    quals_incompat_3[0]["ai_eligible"] = True
    quals_incompat_3[0]["produced_by_allowed"] = ["ai_reasoner"]
    quals_incompat_3[0]["validity_requirements"] = None
    with pytest.raises(RegistryCompilationError, match="empty or missing 'validity_requirements'"):
        validate_source_specification(quals_incompat_3, floors, buckets)


# 7. Invalid scoring bucket fails
def test_7_invalid_scoring_bucket_fails(repo_canonical_sources):
    quals, floors, buckets = repo_canonical_sources
    # 7a: Duplicate bucket_id
    buckets_dup = copy.deepcopy(buckets)
    buckets_dup.append(copy.deepcopy(buckets_dup[0]))
    with pytest.raises(RegistryCompilationError, match="Duplicate scoring bucket_id"):
        validate_source_specification(quals, floors, buckets_dup)

    # 7b: Negative point cap
    buckets_neg = copy.deepcopy(buckets)
    buckets_neg[0]["point_cap"] = -10
    with pytest.raises(RegistryCompilationError, match="point_cap must be a non-negative number"):
        validate_source_specification(quals, floors, buckets_neg)

    # 7c: Invalid bucket max_strength
    buckets_str = copy.deepcopy(buckets)
    buckets_str[0]["max_strength"] = "Ultra"
    with pytest.raises(RegistryCompilationError, match="max_strength 'Ultra' not in valid STRENGTH_ORDER"):
        validate_source_specification(quals, floors, buckets_str)

    # 7d: Unknown bucket category referenced by qualification
    quals_bad_cat = copy.deepcopy(quals)
    quals_bad_cat[0]["category"] = "NonExistentCategory"
    with pytest.raises(RegistryCompilationError, match="references undefined category"):
        validate_source_specification(quals_bad_cat, floors, buckets)

    # 7e: Invalid scoring role
    quals_bad_role = copy.deepcopy(quals)
    quals_bad_role[0]["scoring_role"] = "super_scoreable"
    with pytest.raises(RegistryCompilationError, match="invalid scoring_role 'super_scoreable'"):
        validate_source_specification(quals_bad_role, floors, buckets)

    # 7f: Evidence-only with non-zero weight
    quals_bad_wt = copy.deepcopy(quals)
    quals_bad_wt[0]["scoring_role"] = "evidence_only"
    quals_bad_wt[0]["base_weight"] = 10
    with pytest.raises(RegistryCompilationError, match="scoring_role='evidence_only' but non-zero base_weight"):
        validate_source_specification(quals_bad_wt, floors, buckets)


# 8. Invalid floor operator fails
def test_8_invalid_floor_operator_fails(repo_canonical_sources):
    quals, floors, buckets = repo_canonical_sources
    floors_bad_op = copy.deepcopy(floors)
    floors_bad_op[0]["operator"] = "XOR"
    with pytest.raises(RegistryCompilationError, match="invalid operator 'XOR'"):
        validate_source_specification(quals, floors_bad_op, buckets)


# 9. Deterministic compilation produces identical release content
def test_9_deterministic_compilation_identical_output(tmp_path, repo_canonical_sources):
    quals, floors, buckets = repo_canonical_sources
    src_dir = _setup_source_tree(tmp_path, quals, floors, buckets)
    rel_dir_1 = str(tmp_path / "rel1")
    rel_dir_2 = str(tmp_path / "rel2")

    res1 = compile_registry(src_dir, rel_dir_1, version="v1-det")
    res2 = compile_registry(src_dir, rel_dir_2, version="v1-det")

    with open(res1["snapshot_path"], "rb") as f1, open(res2["snapshot_path"], "rb") as f2:
        bytes1 = f1.read()
        bytes2 = f2.read()

    assert bytes1 == bytes2, "Compilation was not bit-for-bit deterministic!"
    assert res1["digest"] == res2["digest"]


# 10. Release SHA-256 matches actual release bytes
def test_10_release_sha256_matches_actual_bytes(tmp_path, repo_canonical_sources):
    quals, floors, buckets = repo_canonical_sources
    src_dir = _setup_source_tree(tmp_path, quals, floors, buckets)
    rel_dir = str(tmp_path / "releases")

    res = compile_registry(src_dir, rel_dir, version="v1-hashcheck")

    with open(res["snapshot_path"], "rb") as f:
        file_bytes = f.read()
    computed_sha = hashlib.sha256(file_bytes).hexdigest()

    with open(res["sha_path"], "r", encoding="utf-8") as f:
        recorded_sha = f.read().split()[0].strip()

    assert computed_sha == recorded_sha, "Recorded .sha256 does not match SHA-256 of .json bytes!"


# 11. Tampering with release causes loader verification failure
def test_11_tampering_causes_loader_verification_failure(tmp_path, monkeypatch):
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    releases_dir = tmp_path / "releases"
    releases_dir.mkdir(parents=True, exist_ok=True)

    orig_json = os.path.join(repo_root, "01_REGISTRY", "releases", "registry-v1.json")
    orig_sha = os.path.join(repo_root, "01_REGISTRY", "releases", "registry-v1.sha256")

    with open(orig_json, "rb") as f:
        json_bytes = f.read()
    with open(orig_sha, "r", encoding="utf-8") as f:
        sha_text = f.read()

    # Tamper with 1 byte of the JSON
    tampered_bytes = json_bytes.replace(b"v1", b"v2", 1)

    tampered_json_path = releases_dir / "registry-tampered.json"
    tampered_sha_path = releases_dir / "registry-tampered.sha256"

    with open(tampered_json_path, "wb") as f:
        f.write(tampered_bytes)
    with open(tampered_sha_path, "w", encoding="utf-8") as f:
        f.write(sha_text.replace("registry-v1.json", "registry-tampered.json"))

    # Clear cache to ensure clean load
    _REGISTRY_CACHE.clear()

    # Point loader to temporary releases dir
    from hopzero_registry import loader
    monkeypatch.setattr(loader, "get_release_path", lambda v: str(releases_dir / f"registry-{v}.json"))

    with pytest.raises(RegistryVerificationError, match="hash mismatch"):
        load_registry(version="tampered", verify_hash=True)


# Preserve additional invariant test
def test_registry_ontology_invariants():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    release_path = os.path.join(repo_root, "01_REGISTRY", "releases", "registry-v1.json")
    with open(release_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    strengths = ["Negligible", "Weak", "Moderate", "Strong"]
    for q in data["qualifications"]:
        if q["ai_eligible"]:
            assert "ai_reasoner" in q["produced_by_allowed"]
            assert q["validity_requirements"] is not None
        else:
            assert "ai_reasoner" not in q["produced_by_allowed"]

        assert strengths.index(q["default_strength"]) <= strengths.index(q["maximum_strength"])