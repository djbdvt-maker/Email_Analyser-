import pytest

from app.qualification_registry import (
    QualificationEntry, RegistryValidationError, _validate_entry, all_qualifications,
)


def test_main_registry_is_internally_valid():
    """The shipped registry itself must pass its own invariant checks."""
    for entry in all_qualifications().values():
        _validate_entry(entry)  # must not raise


def test_ai_eligible_with_null_validity_requirements_rejected():
    bad_entry = QualificationEntry(
        qualification_code="BAD_QUAL",
        category="Content",
        version="reg-v1",
        ai_eligible=True,
        produced_by_allowed=("ai_reasoner",),
        validity_requirements=None,
        allowed_claim_signatures=("x",),
        default_strength="Weak",
        maximum_strength="Weak",
    )
    with pytest.raises(RegistryValidationError):
        _validate_entry(bad_entry)


def test_ai_eligible_with_empty_validity_requirements_rejected():
    bad_entry = QualificationEntry(
        qualification_code="BAD_QUAL_2",
        category="Content",
        version="reg-v1",
        ai_eligible=True,
        produced_by_allowed=("ai_reasoner",),
        validity_requirements={},
        allowed_claim_signatures=("x",),
        default_strength="Weak",
        maximum_strength="Weak",
    )
    with pytest.raises(RegistryValidationError):
        _validate_entry(bad_entry)


def test_produced_by_allows_ai_reasoner_but_not_ai_eligible_rejected():
    bad_entry = QualificationEntry(
        qualification_code="BAD_QUAL_3",
        category="Content",
        version="reg-v1",
        ai_eligible=False,
        produced_by_allowed=("ai_reasoner",),
        validity_requirements=None,
        allowed_claim_signatures=("x",),
        default_strength="Weak",
        maximum_strength="Weak",
    )
    with pytest.raises(RegistryValidationError):
        _validate_entry(bad_entry)


def test_default_strength_cannot_exceed_maximum_strength():
    bad_entry = QualificationEntry(
        qualification_code="BAD_QUAL_4",
        category="Content",
        version="reg-v1",
        ai_eligible=False,
        produced_by_allowed=("deterministic",),
        validity_requirements=None,
        allowed_claim_signatures=("x",),
        default_strength="Strong",
        maximum_strength="Weak",
    )
    with pytest.raises(RegistryValidationError):
        _validate_entry(bad_entry)


def test_generic_suspicion_max_strength_is_weak():
    from app.qualification_registry import get_qualification
    entry = get_qualification("GENERIC_SUSPICION")
    assert entry.maximum_strength == "Weak"
    assert entry.default_strength == "Weak"
