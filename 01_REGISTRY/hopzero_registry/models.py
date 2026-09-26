from dataclasses import dataclass, field
from typing import Optional, Tuple, Dict, Any

STRENGTH_ORDER = ["Negligible", "Weak", "Moderate", "Strong"]

def strength_at_least(a: str, b: str) -> bool:
    return STRENGTH_ORDER.index(a) >= STRENGTH_ORDER.index(b)

def max_strength(a: str, b: str) -> str:
    return a if STRENGTH_ORDER.index(a) >= STRENGTH_ORDER.index(b) else b

@dataclass(frozen=True)
class StrengthRule:
    target_strength: str
    predicate_names: Tuple[str, ...]

@dataclass(frozen=True)
class QualificationEntry:
    qualification_code: str
    category: str
    version: str
    ai_eligible: bool
    produced_by_allowed: Tuple[str, ...]
    validity_requirements: Optional[Dict[str, Any]]
    allowed_claim_signatures: Tuple[str, ...]
    default_strength: str
    maximum_strength: str
    scoring_role: str = "scoreable"
    base_weight: int = 0
    strength_rules: Tuple[StrengthRule, ...] = field(default_factory=tuple)

@dataclass(frozen=True)
class FloorRequirement:
    qualification_code: str
    min_strength: str = "Moderate"

@dataclass(frozen=True)
class FloorDefinition:
    floor_id: str
    description: str
    target_severity: str
    operator: str
    requirements: Tuple[FloorRequirement, ...]

    @property
    def code(self) -> str:
        return self.floor_id

@dataclass(frozen=True)
class ScoringBucket:
    bucket_id: str
    category: str
    point_cap: int
    max_strength: str