"""
Floor engine.

Floors operate ONLY on already-persisted, validated Finding rows for
an investigation. They never see AICandidate rows, rejected
candidates, model confidence, or model_suggested_strength.

CF-06 is locked as QUALIFIED_ROUTING_FABRICATION (minimum High severity)
and evaluates the three registered deterministic routing fabrication
subtype qualifications:
  - CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE
  - CF-06:INDEPENDENT_TRUSTED_CONTRADICTION
  - CF-06:STRUCTURAL_IMPLAUSIBILITY
plus ROUTING_FABRICATION_QUALIFIED per the canonical registry definitions.
Generic malformed routing headers, unknown IPs, and authentication failures
alone do not satisfy CF-06.
"""
from app.qualification_registry import (
    strength_at_least,
    max_strength,
    get_floors,
    FloorDefinition,
    FloorRequirement,
)

# Canonical floor definitions loaded from authoritative registry
FLOORS: tuple[FloorDefinition, ...] = tuple(get_floors().values())


def evaluate_floors(findings: list) -> list[str]:
    """
    `findings` is a list of persisted Finding ORM rows (or any object
    exposing .qualification_code and .strength) for one investigation.
    Returns the list of triggered floor codes.
    """
    by_qualification: dict[str, str] = {}
    for f in findings:
        existing = by_qualification.get(f.qualification_code)
        by_qualification[f.qualification_code] = (
            f.strength if existing is None else max_strength(existing, f.strength)
        )

    triggered = []
    for floor in FLOORS:
        if floor.operator == "OR":
            satisfied = any(
                (observed := by_qualification.get(req.qualification_code)) is not None
                and strength_at_least(observed, req.min_strength)
                for req in floor.requirements
            )
        else:
            satisfied = all(
                (observed := by_qualification.get(req.qualification_code)) is not None
                and strength_at_least(observed, req.min_strength)
                for req in floor.requirements
            )
        if satisfied:
            # CF-01 semantic requirement: Same protected brand must be involved
            if floor.code == "CF-01":
                lookalike_targets = {
                    (getattr(f, "normalized_target", None) or getattr(f, "normalized_subject_or_target", None) or "").strip().lower()
                    for f in findings
                    if f.qualification_code == "PROTECTED_BRAND_LOOKALIKE_DOMAIN"
                    and strength_at_least(f.strength, "Moderate")
                } - {""}
                claim_targets = {
                    (getattr(f, "normalized_target", None) or getattr(f, "normalized_subject_or_target", None) or "").strip().lower()
                    for f in findings
                    if f.qualification_code == "EXPLICIT_BRAND_REPRESENTATION_CLAIM"
                    and strength_at_least(f.strength, "Moderate")
                } - {""}
                # If explicit target/brand identifiers are provided on both sides, they must intersect
                if lookalike_targets and claim_targets and not (lookalike_targets & claim_targets):
                    satisfied = False

            if satisfied:
                triggered.append(floor.code)
    return triggered


def floor_target_severity(triggered_codes: list) -> str | None:
    if not triggered_codes:
        return None
    by_code = {f.code: f for f in FLOORS}
    severities = [by_code[c].target_severity.upper() for c in triggered_codes if c in by_code]
    if not severities:
        return None
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    return max(severities, key=lambda s: order.index(s) if s in order else 0)
