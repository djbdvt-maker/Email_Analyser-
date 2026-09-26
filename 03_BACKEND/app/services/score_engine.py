"""
The authoritative, backend-owned, deterministic Score Engine (Phase 5 locked specification).

Strictly enforces:
- Exactly 9 scoring buckets with theoretical max 166:
    Identity (20), Authentication (16), Domain (16), URL (22),
    Attachment (20), Infrastructure (14), Routing (20),
    Social Engineering (14), Threat Intelligence (24)
- Locked Base Weights (Tiers 1, 2, 3) and Evidence-Only = 0
- Locked Strength Multipliers: Weak = 0.5x, Moderate = 1.0x, Strong = 1.5x
- Score Normalization: round(raw_score / 166 * 100) clamped to 0–100
- Score-derived Severity: 0–29 LOW, 30–54 MEDIUM, 55–74 HIGH, 75–100 CRITICAL
- Final Severity: MAX(score_severity, highest_applicable_floor)
- Floors do not modify numeric score or add points.
"""
from dataclasses import dataclass
from typing import List, Dict, Optional, Any

from app.qualification_registry import get_category_caps, get_qualification
from app.services.floor_engine import evaluate_floors, floor_target_severity

SCORE_ENGINE_VERSION = "score-engine-v2"
THEORETICAL_MAX_RAW = 166

STRENGTH_MULTIPLIERS: Dict[str, float] = {
    "weak": 0.5,
    "Weak": 0.5,
    "moderate": 1.0,
    "Moderate": 1.0,
    "strong": 1.5,
    "Strong": 1.5,
    "negligible": 0.0,
    "Negligible": 0.0,
}

# Locked 9 Buckets and Caps
DEFAULT_CATEGORY_CAPS: Dict[str, int] = {
    "Identity": 20,
    "Authentication": 16,
    "Domain": 16,
    "URL": 22,
    "Attachment": 20,
    "Infrastructure": 14,
    "Routing": 20,
    "Social Engineering": 14,
    "Threat Intelligence": 24,
}
CATEGORY_CAPS = DEFAULT_CATEGORY_CAPS
STRENGTH_POINTS = STRENGTH_MULTIPLIERS

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def severity_for_score(total_score: int) -> str:
    """Computes score-derived severity from clamped normalized score (0–100)."""
    if total_score <= 29:
        return "LOW"
    if total_score <= 54:
        return "MEDIUM"
    if total_score <= 74:
        return "HIGH"
    return "CRITICAL"


def _max_severity(a: str, b: str) -> str:
    a_norm = a.upper() if a else "LOW"
    b_norm = b.upper() if b else "LOW"
    a_idx = SEVERITY_ORDER.index(a_norm) if a_norm in SEVERITY_ORDER else 0
    b_idx = SEVERITY_ORDER.index(b_norm) if b_norm in SEVERITY_ORDER else 0
    return a_norm if a_idx >= b_idx else b_norm


def _normalize_category(cat: str) -> str:
    if not cat:
        return "Identity"
    cleaned = cat.strip().lower().replace("_", " ").replace("-", " ")
    lookup = {
        "identity": "Identity",
        "authentication": "Authentication",
        "domain": "Domain",
        "url": "URL",
        "links": "URL",
        "link": "URL",
        "attachment": "Attachment",
        "attachments": "Attachment",
        "infrastructure": "Infrastructure",
        "routing": "Routing",
        "routing fabrication": "Routing",
        "routing anomaly": "Routing",
        "social engineering": "Social Engineering",
        "content": "Social Engineering",
        "threat intelligence": "Threat Intelligence",
        "threat intelligence match": "Threat Intelligence",
    }
    return lookup.get(cleaned, cat)


@dataclass
class ScoreResult:
    total_score: int
    severity: str
    category_breakdown: dict
    triggered_floor_codes: list
    finding_ids_used: list
    raw_score: float = 0.0


ScoreOutput = ScoreResult


def compute_score(findings: list) -> ScoreResult:
    """
    Authoritative deterministic numeric scoring according to Phase 5.
    1. Base Weight x Strength Multiplier -> qualification contribution
    2. Group by category bucket -> cap at bucket point_cap
    3. Aggregate capped bucket scores -> raw_score (max 166)
    4. Normalize -> round(raw_score / 166 * 100) clamped to 0–100
    5. Evaluate floors CF-01..CF-06 -> determine final severity = MAX(score_sev, floor_sev)
    """
    reg_caps = get_category_caps()
    category_caps = reg_caps if reg_caps else DEFAULT_CATEGORY_CAPS

    category_totals: Dict[str, float] = {cat: 0.0 for cat in category_caps}
    finding_ids_used: List[str] = []

    for f in findings:
        code = getattr(f, "qualification_code", "") or ""
        strength = getattr(f, "strength", "") or "Moderate"
        raw_cat = getattr(f, "category", "") or ""

        # Determine weight strictly from authoritative compiled registry
        q_def = get_qualification(code)
        if q_def is not None:
            if getattr(q_def, "scoring_role", "scoreable") == "evidence_only":
                base_weight = 0
            else:
                base_weight = getattr(q_def, "base_weight", 0)
        else:
            base_weight = 0

        multiplier = STRENGTH_MULTIPLIERS.get(strength, 1.0)
        contribution = base_weight * multiplier

        # Determine canonical category
        cat = _normalize_category(raw_cat)
        if cat not in category_totals:
            q_def = get_qualification(code)
            if q_def and q_def.category:
                cat = _normalize_category(q_def.category)

        if cat in category_totals:
            category_totals[cat] += contribution

        f_id = getattr(f, "id", None)
        if f_id:
            finding_ids_used.append(str(f_id))

    # Apply bucket caps
    category_breakdown: Dict[str, float] = {}
    raw_score = 0.0
    for category, total in category_totals.items():
        cap = category_caps.get(category, 20)
        capped = min(total, float(cap))
        category_breakdown[category] = capped
        raw_score += capped

    # Normalize: round(raw_score / 166 * 100) clamped 0–100
    total_score = min(100, max(0, int(round((raw_score / THEORETICAL_MAX_RAW) * 100.0))))

    # Evaluate floors (CF-01 through CF-06)
    triggered_floor_codes = evaluate_floors(findings)
    floor_sev = floor_target_severity(triggered_floor_codes)

    # Compute final severity
    score_sev = severity_for_score(total_score)
    if floor_sev is not None:
        final_sev = _max_severity(score_sev, floor_sev)
    else:
        final_sev = score_sev

    return ScoreResult(
        total_score=total_score,
        severity=final_sev,
        category_breakdown=category_breakdown,
        triggered_floor_codes=triggered_floor_codes,
        finding_ids_used=finding_ids_used,
        raw_score=raw_score,
    )




