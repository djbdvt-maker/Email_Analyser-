"""
Qualification registry.

Single source of truth loaded from the canonical compiled registry release
(01_REGISTRY/releases/registry-v1.json) and verified against its cryptographic
SHA-256 digest (registry-v1.sha256).

Eliminates shadow/duplicate qualification registries across components.
"""
from dataclasses import dataclass, field
from typing import Optional, Dict
import os
import sys

# Ensure 01_REGISTRY is in sys.path if not already present
try:
    from hopzero_registry.loader import load_registry, RegistryVerificationError
    from hopzero_registry.models import (
        QualificationEntry,
        StrengthRule,
        FloorDefinition,
        FloorRequirement,
        ScoringBucket,
        STRENGTH_ORDER,
        strength_at_least,
        max_strength,
    )
except ImportError:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    reg_path = os.path.join(repo_root, "01_REGISTRY")
    if reg_path not in sys.path:
        sys.path.insert(0, reg_path)
    from hopzero_registry.loader import load_registry, RegistryVerificationError
    from hopzero_registry.models import (
        QualificationEntry,
        StrengthRule,
        FloorDefinition,
        FloorRequirement,
        ScoringBucket,
        STRENGTH_ORDER,
        strength_at_least,
        max_strength,
    )

REGISTRY_VERSION = "v1"
VALIDITY_RULE_VERSION = "vr-v1"


class RegistryValidationError(Exception):
    """Raised when a registry entry violates the AI-eligibility invariant."""


def _validate_entry(entry: QualificationEntry) -> None:
    """
    Enforces, at load time, the structural AI-eligibility invariant
    from corrections doc P0-4 / V4 P0-4:

        ai_eligible == True
        AND validity_requirements exists
        AND validity_requirements is non-empty
        AND validity_requirements is structurally valid
        (AND if "ai_reasoner" in produced_by_allowed, the above must hold)
    """
    if entry.ai_eligible:
        if not entry.validity_requirements:
            raise RegistryValidationError(
                f"{entry.qualification_code}: ai_eligible=True requires a "
                f"non-empty validity_requirements block."
            )
        if "disqualifier_phrases" not in entry.validity_requirements:
            raise RegistryValidationError(
                f"{entry.qualification_code}: validity_requirements is "
                f"structurally invalid (missing 'disqualifier_phrases')."
            )

    if "ai_reasoner" in entry.produced_by_allowed and not entry.ai_eligible:
        raise RegistryValidationError(
            f"{entry.qualification_code}: produced_by_allowed includes "
            f"'ai_reasoner' but ai_eligible is False/missing validity "
            f"requirements."
        )

    if entry.default_strength not in STRENGTH_ORDER or entry.maximum_strength not in STRENGTH_ORDER:
        raise RegistryValidationError(f"{entry.qualification_code}: invalid strength value.")

    if STRENGTH_ORDER.index(entry.default_strength) > STRENGTH_ORDER.index(entry.maximum_strength):
        raise RegistryValidationError(
            f"{entry.qualification_code}: default_strength cannot exceed maximum_strength."
        )


def _load_and_validate_registry() -> tuple[
    dict[str, QualificationEntry],
    dict[str, str],
    dict[str, FloorDefinition],
    dict[str, ScoringBucket],
]:
    reg = load_registry(version="v1", verify_hash=True)
    raw_quals = reg["qualifications"]
    validated: dict[str, QualificationEntry] = {}

    for code, entry in raw_quals.items():
        _validate_entry(entry)
        validated[code] = entry

    scoring_buckets = reg.get("scoring_buckets", {})
    bucket_caps: dict[str, str] = {}
    for cat, b in scoring_buckets.items():
        bucket_caps[cat] = getattr(b, "max_strength", "Strong")

    floors = reg.get("floors", {})
    return validated, bucket_caps, floors, scoring_buckets


_ENTRIES, _BUCKET_MAX_STRENGTH, _FLOORS, _SCORING_BUCKETS = _load_and_validate_registry()


def get_qualification(qualification_code: str) -> Optional[QualificationEntry]:
    return _ENTRIES.get(qualification_code)


def all_qualifications() -> dict[str, QualificationEntry]:
    return dict(_ENTRIES)


def get_bucket_max_strength(category: str) -> Optional[str]:
    return _BUCKET_MAX_STRENGTH.get(category)


def get_floors() -> dict[str, FloorDefinition]:
    return dict(_FLOORS)


def get_scoring_buckets() -> dict[str, ScoringBucket]:
    return dict(_SCORING_BUCKETS)


def get_category_caps() -> dict[str, int]:
    return {cat: b.point_cap for cat, b in _SCORING_BUCKETS.items()}
