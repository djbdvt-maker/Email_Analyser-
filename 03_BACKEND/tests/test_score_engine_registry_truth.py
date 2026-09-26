"""
Tests for Score Engine Registry Authority & Source of Truth (Section 17).
========================================================================
Proves:
- Compiled qualification registry is authoritative.
- Every scoreable Q has a valid positive base_weight matching locked specification.
- Every evidence-only Q has base_weight 0.
- No unknown qualification receives points.
- Registry and runtime scoring agree.
"""
from dataclasses import dataclass
import pytest

from app.qualification_registry import all_qualifications, get_qualification
from app.services.score_engine import (
    compute_score,
    THEORETICAL_MAX_RAW,
    DEFAULT_CATEGORY_CAPS,
)


@dataclass
class _MockFinding:
    id: str
    category: str
    strength: str
    qualification_code: str


def test_registry_contains_qualifications():
    """Verify registry loads correctly."""
    quals = all_qualifications()
    assert len(quals) >= 41


def test_every_scoreable_qualification_has_positive_base_weight():
    """Every scoreable qualification in compiled registry must have positive base_weight."""
    quals = all_qualifications()
    for code, q in quals.items():
        if q.scoring_role == "scoreable":
            assert q.base_weight > 0, f"Scoreable qualification {code} has non-positive base_weight: {q.base_weight}"


def test_every_evidence_only_qualification_has_zero_base_weight():
    """Every evidence-only qualification in compiled registry must have base_weight == 0."""
    quals = all_qualifications()
    for code, q in quals.items():
        if q.scoring_role == "evidence_only":
            assert q.base_weight == 0, f"Evidence-only qualification {code} has non-zero base_weight: {q.base_weight}"


def test_unknown_qualification_receives_zero_points():
    """An unknown qualification code must contribute exactly 0 raw points and 0 score."""
    findings = [
        _MockFinding(
            id="unknown-1",
            category="Identity",
            strength="Strong",
            qualification_code="NON_EXISTENT_QUALIFICATION_XYZ",
        ),
        _MockFinding(
            id="unknown-2",
            category="Threat Intelligence",
            strength="Strong",
            qualification_code="FABRICATED_AI_CODE_123",
        ),
    ]
    result = compute_score(findings)
    assert result.raw_score == 0.0
    assert result.total_score == 0
    assert result.severity == "LOW"


def test_evidence_only_finding_receives_zero_points_at_runtime():
    """Runtime scoring must grant 0 points for evidence-only findings regardless of strength."""
    findings = [
        _MockFinding(
            id="ev-1",
            category="Social Engineering",
            strength="Strong",
            qualification_code="GENERIC_SUSPICION",
        ),
        _MockFinding(
            id="ev-2",
            category="Domain",
            strength="Strong",
            qualification_code="PUNYCODE_DOMAIN_INDICATOR",
        ),
        _MockFinding(
            id="ev-3",
            category="URL",
            strength="Strong",
            qualification_code="URL_SHORTENER_DETECTED",
        ),
    ]
    result = compute_score(findings)
    assert result.raw_score == 0.0
    assert result.total_score == 0
    assert result.severity == "LOW"


def test_locked_strength_multipliers():
    """Locked multipliers: Weak=0.5x, Moderate=1.0x, Strong=1.5x."""
    # FINANCIAL_REQUEST base_weight is 8 in registry
    weak_f = [_MockFinding(id="f1", category="Social Engineering", strength="Weak", qualification_code="FINANCIAL_REQUEST")]
    mod_f = [_MockFinding(id="f2", category="Social Engineering", strength="Moderate", qualification_code="FINANCIAL_REQUEST")]
    str_f = [_MockFinding(id="f3", category="Social Engineering", strength="Strong", qualification_code="FINANCIAL_REQUEST")]

    res_weak = compute_score(weak_f)
    res_mod = compute_score(mod_f)
    res_str = compute_score(str_f)

    assert res_weak.raw_score == 4.0   # 8 * 0.5
    assert res_mod.raw_score == 8.0    # 8 * 1.0
    assert res_str.raw_score == 12.0   # 8 * 1.5


def test_category_caps_applied_per_registry():
    """Bucket caps are applied from the registry."""
    # Identity cap is 20
    # Two Strong EXECUTIVE_IMPERSONATION (16 * 1.5 = 24 each = 48 total)
    findings = [
        _MockFinding(id="f1", category="Identity", strength="Strong", qualification_code="EXECUTIVE_IMPERSONATION"),
        _MockFinding(id="f2", category="Identity", strength="Strong", qualification_code="EXECUTIVE_IMPERSONATION"),
    ]
    result = compute_score(findings)
    assert result.category_breakdown["Identity"] == 20.0
    assert result.raw_score == 20.0
    assert result.total_score == round((20.0 / 166.0) * 100)
