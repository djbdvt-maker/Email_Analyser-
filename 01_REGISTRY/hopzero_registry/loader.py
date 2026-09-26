import os
import json
import hashlib
from typing import Optional, Dict
from .models import (
    QualificationEntry, StrengthRule, FloorDefinition,
    FloorRequirement, ScoringBucket, STRENGTH_ORDER,
    strength_at_least, max_strength
)

class RegistryVerificationError(Exception):
    pass

_REGISTRY_CACHE: Dict[str, dict] = {}

def get_release_path(version: str = "v1") -> str:
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "releases"))
    return os.path.join(base, f"registry-{version}.json")

def load_registry(version: str = "v1", verify_hash: bool = True) -> dict:
    if version in _REGISTRY_CACHE:
        return _REGISTRY_CACHE[version]

    json_path = get_release_path(version)
    sha_path = json_path.replace(".json", ".sha256")

    if not os.path.exists(json_path):
        raise FileNotFoundError(f"Compiled registry snapshot not found at {json_path}")

    with open(json_path, "rb") as f:
        raw_bytes = f.read()

    computed_digest = hashlib.sha256(raw_bytes).hexdigest()

    if verify_hash and os.path.exists(sha_path):
        with open(sha_path, "r", encoding="utf-8") as f:
            expected_digest = f.read().split()[0].strip()
        if computed_digest != expected_digest:
            raise RegistryVerificationError(
                f"Registry {version} hash mismatch! Expected {expected_digest}, computed {computed_digest}"
            )

    data = json.loads(raw_bytes.decode("utf-8"))

    qualifications: Dict[str, QualificationEntry] = {}
    for q in data.get("qualifications", []):
        rules = tuple(
            StrengthRule(target_strength=r["target_strength"], predicate_names=tuple(r["predicate_names"]))
            for r in q.get("strength_rules", [])
        )
        entry = QualificationEntry(
            qualification_code=q["qualification_code"],
            category=q["category"],
            version=q.get("version", version),
            ai_eligible=q["ai_eligible"],
            produced_by_allowed=tuple(q["produced_by_allowed"]),
            validity_requirements=q.get("validity_requirements"),
            allowed_claim_signatures=tuple(q.get("allowed_claim_signatures", [])),
            default_strength=q["default_strength"],
            maximum_strength=q["maximum_strength"],
            scoring_role=q.get("scoring_role", "scoreable"),
            base_weight=q.get("base_weight", 0),
            strength_rules=rules,
        )
        qualifications[entry.qualification_code] = entry

    floors: Dict[str, FloorDefinition] = {}
    for fl in data.get("floors", []):
        reqs = tuple(
            FloorRequirement(qualification_code=r["qualification_code"], min_strength=r.get("min_strength", "Moderate"))
            for r in fl.get("requirements", [])
        )
        floors[fl["floor_id"]] = FloorDefinition(
            floor_id=fl["floor_id"],
            description=fl.get("description", ""),
            target_severity=fl.get("target_severity", "High"),
            operator=fl.get("operator", "AND"),
            requirements=reqs,
        )

    scoring_buckets: Dict[str, ScoringBucket] = {}
    for sb in data.get("scoring_buckets", []):
        scoring_buckets[sb["category"]] = ScoringBucket(
            bucket_id=sb["bucket_id"],
            category=sb["category"],
            point_cap=sb["point_cap"],
            max_strength=sb.get("max_strength", "Strong"),
        )

    registry_obj = {
        "version": data.get("registry_version", version),
        "hash": f"sha256:{computed_digest}",
        "content_sha256": computed_digest,
        "qualifications": qualifications,
        "floors": floors,
        "scoring_buckets": scoring_buckets,
    }
    _REGISTRY_CACHE[version] = registry_obj
    return registry_obj

def get_qualification(code: str, version: str = "v1") -> Optional[QualificationEntry]:
    reg = load_registry(version)
    return reg["qualifications"].get(code)

def all_qualifications(version: str = "v1") -> Dict[str, QualificationEntry]:
    return dict(load_registry(version)["qualifications"])

def get_floors(version: str = "v1") -> Dict[str, FloorDefinition]:
    return dict(load_registry(version)["floors"])

def get_scoring_buckets(version: str = "v1") -> Dict[str, ScoringBucket]:
    return dict(load_registry(version)["scoring_buckets"])