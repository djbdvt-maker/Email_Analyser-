"""
Authoritative Qualification Registry Compatibility Shim.
=======================================================
Per P1 #4: There must not be a second competing hand-written qualification ontology.
The authoritative registry is hopzero-registry + compiled registry snapshot
(01_REGISTRY/releases/registry-v1.json).

This module delegates directly to app.qualification_registry to ensure
ONE single source of truth across the backend and pipeline.
"""
from app.qualification_registry import (
    REGISTRY_VERSION,
    VALIDITY_RULE_VERSION,
    RegistryValidationError,
    QualificationEntry,
    StrengthRule,
    STRENGTH_ORDER,
    strength_at_least,
    max_strength,
    get_qualification,
    all_qualifications,
)

__all__ = [
    "REGISTRY_VERSION",
    "VALIDITY_RULE_VERSION",
    "RegistryValidationError",
    "QualificationEntry",
    "StrengthRule",
    "STRENGTH_ORDER",
    "strength_at_least",
    "max_strength",
    "get_qualification",
    "all_qualifications",
]
