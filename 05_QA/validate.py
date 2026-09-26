#!/usr/bin/env python3
"""
Standalone validator for SECURITY_EVALUATION_CORPUS_V1 (corpus.json).

Run: python3 validate.py [path/to/corpus.json]

This performs BASIC SANITY / SCHEMA validation only, per the task
instruction not to build the full automated regression suite yet. It does
NOT evaluate any implementation against the corpus - it only checks that
the corpus file itself is well-formed and respects the boundary discipline
(no invented qualification codes/signatures/strengths/scores; every case
traceable to a source; confirmation_level never claims B/C/D).
"""
import json
import os
import sys
from collections import Counter


REQUIRED_FIELDS = [
    "case_id", "title", "scenario_type", "input_description",
    "expected_behavior", "expected_concepts", "expected_qualification_code",
    "expected_claim_signature", "expected_strength", "expected_score",
    "expected_severity", "ai_relevant", "evasion_class", "notes",
    "source_references", "confirmation_level",
]

NEVER_FILLED_FIELDS = [
    "expected_qualification_code", "expected_claim_signature",
    "expected_strength", "expected_score",
]

VALID_CONFIRMATION_LEVELS = {"A", "B", "C", "D", "E"}
DISALLOWED_CONFIRMATION_LEVELS = {"B", "C", "D"}


def validate(path):
    errors = []
    warnings = []

    with open(path) as f:
        data = json.load(f)

    cases = data.get("cases", [])
    declared_total = data.get("total_cases")
    if declared_total != len(cases):
        errors.append(
            f"total_cases ({declared_total}) does not match len(cases) ({len(cases)})"
        )

    ids = []
    for i, c in enumerate(cases):
        loc = c.get("case_id", f"<index {i}>")

        # Required fields present
        for field in REQUIRED_FIELDS:
            if field not in c:
                errors.append(f"{loc}: missing required field '{field}'")

        # Boundary discipline
        for field in NEVER_FILLED_FIELDS:
            if c.get(field) is not None:
                errors.append(
                    f"{loc}: '{field}' is not null ({c.get(field)!r}) - "
                    f"this corpus must never assert qualification codes, "
                    f"claim signatures, strengths, or scores"
                )

        # Non-empty behavior/concepts/sources
        if not c.get("expected_behavior"):
            errors.append(f"{loc}: expected_behavior is empty")
        if not c.get("expected_concepts"):
            errors.append(f"{loc}: expected_concepts is empty")
        if not c.get("source_references"):
            errors.append(f"{loc}: source_references is empty (every case must be traceable)")

        # confirmation_level discipline
        levels = set(c.get("confirmation_level", []))
        bad_levels = levels - VALID_CONFIRMATION_LEVELS
        if bad_levels:
            errors.append(f"{loc}: invalid confirmation_level entries {bad_levels}")
        disallowed = levels & DISALLOWED_CONFIRMATION_LEVELS
        if disallowed:
            errors.append(
                f"{loc}: confirmation_level claims {disallowed} - this corpus "
                f"is not authorized to confirm exact codes/signatures/strengths"
            )
        if levels and "A" not in levels:
            warnings.append(
                f"{loc}: confirmation_level {levels} does not include 'A' - "
                f"unusual, since every case should at least have the concept confirmed"
            )

        # expected_severity, when present, should read as directional prose,
        # not a bare numeric score (best-effort heuristic warning only)
        sev = c.get("expected_severity")
        if isinstance(sev, (int, float)):
            errors.append(f"{loc}: expected_severity is a bare number ({sev}) - must be directional/qualitative, never an exact score")

        ids.append(c.get("case_id"))

    dupes = [cid for cid, n in Counter(ids).items() if n > 1]
    if dupes:
        errors.append(f"Duplicate case_id(s): {dupes}")

    print(f"Checked {len(cases)} cases from {path}")
    if warnings:
        print(f"\n{len(warnings)} WARNING(S):")
        for w in warnings:
            print(" -", w)
    if errors:
        print(f"\n{len(errors)} ERROR(S):")
        for e in errors:
            print(" -", e)
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    default_path = os.path.join(os.path.dirname(__file__), "corpus.json") if not os.path.exists("corpus.json") else "corpus.json"
    path = sys.argv[1] if len(sys.argv) > 1 else default_path
    sys.exit(validate(path))

