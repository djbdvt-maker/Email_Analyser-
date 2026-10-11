"""
HopZero Core - Qualification Registry Loader & Models.
======================================================
Single source of truth for qualification codes, severity levels, strength rules,
critical floors (CF-01..CF-06), and scoring category caps.
Verifies the cryptographic SHA-256 digest of the compiled snapshot upon load.
"""
import os
import sys
from typing import Dict, Optional

# Locate registry directory
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_CURRENT_DIR, "..", ".."))
_REG_DIR = os.path.join(_REPO_ROOT, "01_REGISTRY")
if _REG_DIR not in sys.path:
    sys.path.insert(0, _REG_DIR)

from hopzero_registry.loader import (
    load_registry,
    get_qualification,
    all_qualifications,
    get_floors,
    get_scoring_buckets,
    RegistryVerificationError,
)
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

__all__ = [
    "load_registry",
    "get_qualification",
    "all_qualifications",
    "get_floors",
    "get_scoring_buckets",
    "RegistryVerificationError",
    "QualificationEntry",
    "StrengthRule",
    "FloorDefinition",
    "FloorRequirement",
    "ScoringBucket",
    "STRENGTH_ORDER",
    "strength_at_least",
    "max_strength",
]
