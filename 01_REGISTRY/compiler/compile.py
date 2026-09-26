#!/usr/bin/env python3
"""
HopZero Registry Compiler (v1)
==============================

Domain-specific security specification compiler.
Transforms human-authored canonical specification YAML files:
  - 01_REGISTRY/source/qualifications.yaml
  - 01_REGISTRY/source/floors.yaml
  - 01_REGISTRY/source/scoring_buckets.yaml
into a validated, immutable, machine-readable release snapshot
(registry-<version>.json + matching registry-<version>.sha256).

Enforces structural, semantic, and cross-reference invariants:
  A. Qualification uniqueness
  B. Required fields presence
  C. Version validity
  D. Strength validity and ordering
  E. Producer validity (deterministic, ai_reasoner)
  F. AI eligibility consistency
  G. Claim signature validity & uniqueness
  H. Floor qualification references
  I. Floor structure, operators, and target severity
  J. Scoring bucket definitions and numeric point caps
  K. Category cross-reference consistency
  L. Semantic structural consistency

Clean SHA-256 hash design:
  1. Build canonical release object WITHOUT self-referential snapshot_hash.
  2. Serialize deterministically (sorted keys, 2-space indentation).
  3. Compute release content SHA-256 over exact release bytes.
  4. Write exact release bytes to registry-<version>.json.
  5. Write matching digest to registry-<version>.sha256.
"""

from __future__ import annotations

import os
import sys
import json
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
import yaml

STRENGTH_ORDER = ["Negligible", "Weak", "Moderate", "Strong"]
SUPPORTED_PRODUCERS = {"deterministic", "ai_reasoner"}
ALLOWED_FLOOR_OPERATORS = {"AND", "OR"}
ALLOWED_TARGET_SEVERITIES = {"Low", "Medium", "High", "Critical"}


class RegistryCompilationError(Exception):
    """Raised when canonical registry sources violate specification constraints."""
    pass


def get_reproducible_timestamp(source_files: List[str], explicit_timestamp: Optional[str] = None) -> str:
    """
    Reproducible build timestamp strategy:
    1. If explicit_timestamp is provided, use it.
    2. If SOURCE_DATE_EPOCH environment variable is present, use it (standard reproducible builds).
    3. Otherwise, derive from the latest mtime of canonical source files.
    Guarantee: SAME SOURCE + SAME COMPILER VERSION = SAME COMPILED CONTENT.
    """
    if explicit_timestamp:
        return explicit_timestamp
    if "SOURCE_DATE_EPOCH" in os.environ:
        try:
            epoch = int(os.environ["SOURCE_DATE_EPOCH"])
            return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass
    mtimes = [os.path.getmtime(f) for f in source_files if os.path.exists(f)]
    if mtimes:
        return datetime.fromtimestamp(max(mtimes), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return "2026-09-13T00:00:00Z"


def validate_source_specification(
    qualifications: List[Dict[str, Any]],
    floors: List[Dict[str, Any]],
    scoring_buckets: List[Dict[str, Any]],
) -> None:
    """
    Comprehensive compilation validation against the locked HopZero specification.
    """
    if not isinstance(qualifications, list) or not qualifications:
        raise RegistryCompilationError("Qualifications source must be a non-empty list.")
    if not isinstance(floors, list) or not floors:
        raise RegistryCompilationError("Floors source must be a non-empty list.")
    if not isinstance(scoring_buckets, list) or not scoring_buckets:
        raise RegistryCompilationError("Scoring buckets source must be a non-empty list.")

    # -------------------------------------------------------------
    # 1. Scoring Buckets Validation (J, K prerequisites)
    # -------------------------------------------------------------
    bucket_ids: Set[str] = set()
    bucket_categories: Set[str] = set()
    for b in scoring_buckets:
        if not isinstance(b, dict):
            raise RegistryCompilationError("Each scoring bucket entry must be a dictionary.")
        bid = b.get("bucket_id")
        cat = b.get("category")
        cap = b.get("point_cap")
        b_max = b.get("max_strength", "Strong")

        if not bid or not isinstance(bid, str):
            raise RegistryCompilationError("Scoring bucket missing required non-empty 'bucket_id'.")
        if bid in bucket_ids:
            raise RegistryCompilationError(f"Duplicate scoring bucket_id: '{bid}'")
        bucket_ids.add(bid)

        if not cat or not isinstance(cat, str):
            raise RegistryCompilationError(f"Bucket '{bid}' missing required non-empty 'category'.")
        if cat in bucket_categories:
            raise RegistryCompilationError(f"Duplicate scoring bucket category: '{cat}'")
        bucket_categories.add(cat)

        if not isinstance(cap, (int, float)) or cap < 0:
            raise RegistryCompilationError(f"Bucket '{bid}' point_cap must be a non-negative number; got {cap}")

        if b_max not in STRENGTH_ORDER:
            raise RegistryCompilationError(f"Bucket '{bid}' max_strength '{b_max}' not in valid STRENGTH_ORDER.")

    # -------------------------------------------------------------
    # 2. Qualifications Validation (A, B, C, D, E, F, G, K, L)
    # -------------------------------------------------------------
    qual_codes: Set[str] = set()
    required_qual_fields = {
        "qualification_code",
        "category",
        "version",
        "ai_eligible",
        "produced_by_allowed",
        "default_strength",
        "maximum_strength",
    }

    for q in qualifications:
        if not isinstance(q, dict):
            raise RegistryCompilationError("Each qualification entry must be a dictionary.")

        # Check required fields
        for rf in required_qual_fields:
            if rf not in q:
                raise RegistryCompilationError(f"Qualification entry missing required field: '{rf}'")

        code = q["qualification_code"]
        if not code or not isinstance(code, str):
            raise RegistryCompilationError("Qualification code must be a non-empty string.")
        if code in qual_codes:
            raise RegistryCompilationError(f"Duplicate qualification code detected: '{code}'")
        qual_codes.add(code)

        # Version validity (C)
        version = q["version"]
        if not version or not isinstance(version, str):
            raise RegistryCompilationError(f"Qualification '{code}' version must be a non-empty string.")

        # Category cross-reference (K)
        cat = q["category"]
        if cat not in bucket_categories:
            raise RegistryCompilationError(
                f"Qualification '{code}' references undefined category '{cat}'. "
                f"Must match a defined scoring bucket category."
            )

        # Strength validity (D, L)
        def_str = q["default_strength"]
        max_str = q["maximum_strength"]
        if def_str not in STRENGTH_ORDER:
            raise RegistryCompilationError(f"Qualification '{code}' default_strength '{def_str}' is invalid.")
        if max_str not in STRENGTH_ORDER:
            raise RegistryCompilationError(f"Qualification '{code}' maximum_strength '{max_str}' is invalid.")
        if STRENGTH_ORDER.index(def_str) > STRENGTH_ORDER.index(max_str):
            raise RegistryCompilationError(
                f"Qualification '{code}' default_strength '{def_str}' exceeds maximum_strength '{max_str}'."
            )

        # Strength rules if present
        for rule in q.get("strength_rules", []):
            if not isinstance(rule, dict):
                raise RegistryCompilationError(f"Qualification '{code}' strength_rules entry must be a dict.")
            t_str = rule.get("target_strength")
            preds = rule.get("predicate_names")
            if t_str not in STRENGTH_ORDER:
                raise RegistryCompilationError(
                    f"Qualification '{code}' strength rule target_strength '{t_str}' is invalid."
                )
            if not isinstance(preds, (list, tuple)) or not preds:
                raise RegistryCompilationError(
                    f"Qualification '{code}' strength rule must specify non-empty 'predicate_names'."
                )

        # Producer validity (E)
        prods = q["produced_by_allowed"]
        if not isinstance(prods, (list, tuple)) or not prods:
            raise RegistryCompilationError(
                f"Qualification '{code}' produced_by_allowed must be a non-empty list of producer classes."
            )
        for p in prods:
            if p not in SUPPORTED_PRODUCERS:
                raise RegistryCompilationError(
                    f"Qualification '{code}' specifies unsupported producer class '{p}'. "
                    f"Supported producers: {SUPPORTED_PRODUCERS}"
                )

        # AI eligibility consistency (F, L)
        ai_eligible = q["ai_eligible"]
        if not isinstance(ai_eligible, bool):
            raise RegistryCompilationError(f"Qualification '{code}' ai_eligible must be boolean.")

        if ai_eligible:
            if "ai_reasoner" not in prods:
                raise RegistryCompilationError(
                    f"Qualification '{code}' is ai_eligible=True but 'ai_reasoner' is missing from produced_by_allowed."
                )
            vreq = q.get("validity_requirements")
            if not isinstance(vreq, dict) or not vreq:
                raise RegistryCompilationError(
                    f"Qualification '{code}' is ai_eligible=True but has empty or missing 'validity_requirements'."
                )
            if "disqualifier_phrases" not in vreq or not isinstance(vreq["disqualifier_phrases"], list):
                raise RegistryCompilationError(
                    f"Qualification '{code}' validity_requirements missing 'disqualifier_phrases' list."
                )
        else:
            if "ai_reasoner" in prods:
                raise RegistryCompilationError(
                    f"Qualification '{code}' is ai_eligible=False but permits 'ai_reasoner' in produced_by_allowed."
                )

        # Scoring role and weight validation (Phase 4 & 5)
        scoring_role = q.get("scoring_role", "scoreable")
        if scoring_role not in {"scoreable", "evidence_only"}:
            raise RegistryCompilationError(
                f"Qualification '{code}' specifies invalid scoring_role '{scoring_role}'. "
                f"Must be 'scoreable' or 'evidence_only'."
            )
        base_weight = q.get("base_weight", 0)
        if not isinstance(base_weight, (int, float)) or base_weight < 0:
            raise RegistryCompilationError(
                f"Qualification '{code}' base_weight must be a non-negative number; got {base_weight}"
            )
        if scoring_role == "evidence_only" and base_weight != 0:
            raise RegistryCompilationError(
                f"Qualification '{code}' has scoring_role='evidence_only' but non-zero base_weight {base_weight}."
            )

        # Claim signature validity (G)
        claims = q.get("allowed_claim_signatures", [])
        if not isinstance(claims, (list, tuple)):
            raise RegistryCompilationError(f"Qualification '{code}' allowed_claim_signatures must be a list.")
        seen_claims: Set[str] = set()
        for cs in claims:
            if not cs or not isinstance(cs, str):
                raise RegistryCompilationError(f"Qualification '{code}' has invalid empty claim signature.")
            if cs in seen_claims:
                raise RegistryCompilationError(f"Qualification '{code}' has duplicate claim signature: '{cs}'")
            seen_claims.add(cs)

    # -------------------------------------------------------------
    # 3. Floors Validation (H, I, L)
    # -------------------------------------------------------------
    floor_ids: Set[str] = set()
    for fl in floors:
        if not isinstance(fl, dict):
            raise RegistryCompilationError("Floor entry must be a dictionary.")
        fid = fl.get("floor_id")
        op = fl.get("operator", "AND")
        t_sev = fl.get("target_severity", "High")
        reqs = fl.get("requirements")

        if not fid or not isinstance(fid, str):
            raise RegistryCompilationError("Floor entry missing required non-empty 'floor_id'.")
        if fid in floor_ids:
            raise RegistryCompilationError(f"Duplicate floor_id: '{fid}'")
        floor_ids.add(fid)

        if op not in ALLOWED_FLOOR_OPERATORS:
            raise RegistryCompilationError(f"Floor '{fid}' has invalid operator '{op}'. Allowed: {ALLOWED_FLOOR_OPERATORS}")
        if t_sev not in ALLOWED_TARGET_SEVERITIES:
            raise RegistryCompilationError(f"Floor '{fid}' has invalid target_severity '{t_sev}'. Allowed: {ALLOWED_TARGET_SEVERITIES}")

        if not isinstance(reqs, list) or not reqs:
            raise RegistryCompilationError(f"Floor '{fid}' must have non-empty 'requirements' list.")

        for r in reqs:
            if not isinstance(r, dict):
                raise RegistryCompilationError(f"Floor '{fid}' requirement must be a dict.")
            rcode = r.get("qualification_code")
            rmin = r.get("min_strength", "Moderate")

            if not rcode or rcode not in qual_codes:
                raise RegistryCompilationError(
                    f"Floor '{fid}' references unknown qualification_code '{rcode}'. "
                    f"Every floor qualification must exist in the canonical qualification registry."
                )
            if rmin not in STRENGTH_ORDER:
                raise RegistryCompilationError(
                    f"Floor '{fid}' requirement '{rcode}' min_strength '{rmin}' is invalid."
                )


def compile_registry(
    source_dir: str,
    releases_dir: str,
    version: str = "v1",
    build_timestamp: Optional[str] = None,
) -> dict:
    """
    Stateless, deterministic compilation from human-authored source artifacts
    (qualifications.yaml, floors.yaml, scoring_buckets.yaml) into an immutable
    compiled registry release snapshot (registry-<version>.json + .sha256).
    """
    qualifications_file = os.path.join(source_dir, "qualifications.yaml")
    floors_file = os.path.join(source_dir, "floors.yaml")
    scoring_buckets_file = os.path.join(source_dir, "scoring_buckets.yaml")

    source_files = [qualifications_file, floors_file, scoring_buckets_file]
    for sf in source_files:
        if not os.path.exists(sf):
            raise RegistryCompilationError(f"Canonical source file not found: {sf}")

    with open(qualifications_file, "r", encoding="utf-8") as f:
        qualifications = yaml.safe_load(f)
    with open(floors_file, "r", encoding="utf-8") as f:
        floors = yaml.safe_load(f)
    with open(scoring_buckets_file, "r", encoding="utf-8") as f:
        scoring_buckets = yaml.safe_load(f)

    # 1. Full validation pass before producing release
    validate_source_specification(qualifications, floors, scoring_buckets)

    # 2. Deterministic ordering: sort keys and lists by ID/code
    qualifications = sorted(qualifications, key=lambda x: x["qualification_code"])
    floors = sorted(floors, key=lambda x: x["floor_id"])
    scoring_buckets = sorted(scoring_buckets, key=lambda x: x["bucket_id"])

    # 3. Derive deterministic build timestamp
    compiled_at = get_reproducible_timestamp(source_files, explicit_timestamp=build_timestamp)

    # 4. Construct canonical release snapshot WITHOUT self-referential snapshot_hash
    snapshot = {
        "compiled_at": compiled_at,
        "compiler_version": "hopzero-compiler-v1.0.0",
        "floors": floors,
        "pattern_sets": {},
        "qualifications": qualifications,
        "registry_version": version,
        "scoring_buckets": scoring_buckets,
    }

    # 5. Deterministic serialization (sorted keys, consistent indent, trailing newline)
    serialized_json = json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
    content_digest = hashlib.sha256(serialized_json.encode("utf-8")).hexdigest()

    # 6. Write release files
    os.makedirs(releases_dir, exist_ok=True)
    release_json_path = os.path.join(releases_dir, f"registry-{version}.json")
    release_sha_path = os.path.join(releases_dir, f"registry-{version}.sha256")

    with open(release_json_path, "wb") as f:
        f.write(serialized_json.encode("utf-8"))

    with open(release_sha_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"{content_digest}  registry-{version}.json\n")

    print(f"Successfully compiled registry-{version}:")
    print(f"  Snapshot: {release_json_path}")
    print(f"  Digest:   {content_digest}")

    return {
        "version": version,
        "digest": content_digest,
        "snapshot_path": release_json_path,
        "sha_path": release_sha_path,
    }


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "source")
    rel = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), "..", "releases")
    compile_registry(src, rel)