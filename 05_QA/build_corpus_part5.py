import json
import sys
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# Sanity checks (basic validation only, per instruction - not a full
# automated regression suite)
# ---------------------------------------------------------------------------

errors = []

# 1. Case count
if len(CASES) != 85:
    errors.append(f"Expected 85 cases, found {len(CASES)}")

# 2. Unique case_id
ids = [c["case_id"] for c in CASES]
dupes = [cid for cid, n in Counter(ids).items() if n > 1]
if dupes:
    errors.append(f"Duplicate case_id(s): {dupes}")

# 3. Boundary discipline: expected_qualification_code / claim_signature /
#    strength / score must ALWAYS be null - the corpus must never invent
#    these regardless of confirmation_level.
for c in CASES:
    for field in ("expected_qualification_code", "expected_claim_signature",
                  "expected_strength", "expected_score"):
        if c[field] is not None:
            errors.append(f"{c['case_id']}: {field} is not null ({c[field]!r}) - boundary violation")

# 4. Every case must have at least one source reference
for c in CASES:
    if not c["source_references"]:
        errors.append(f"{c['case_id']}: no source_references")

# 5. Every case must have non-empty expected_behavior and expected_concepts
for c in CASES:
    if not c["expected_behavior"]:
        errors.append(f"{c['case_id']}: empty expected_behavior")
    if not c["expected_concepts"]:
        errors.append(f"{c['case_id']}: empty expected_concepts")

# 6. confirmation_level values must be subset of {A,B,C,D,E}
valid_levels = {"A", "B", "C", "D", "E"}
for c in CASES:
    bad = set(c["confirmation_level"]) - valid_levels
    if bad:
        errors.append(f"{c['case_id']}: invalid confirmation_level entries {bad}")

# 7. No confirmation_level should include B, C, or D anywhere in this corpus
#    (qualification code / claim signature / strength are never confirmed
#    per the task's own boundary - if this ever fires, it means a case was
#    marked as confirming something QA is not authorized to confirm).
for c in CASES:
    if set(c["confirmation_level"]) & {"B", "C", "D"}:
        errors.append(f"{c['case_id']}: confirmation_level includes B/C/D - not permitted for this corpus")

if errors:
    print("VALIDATION ERRORS:")
    for e in errors:
        print(" -", e)
    sys.exit(1)

print(f"All basic sanity checks passed. {len(CASES)} cases.")

# ---------------------------------------------------------------------------
# Write corpus.json
# ---------------------------------------------------------------------------

corpus = {
    "corpus_name": "SECURITY_EVALUATION_CORPUS_V1",
    "corpus_version": "1.0.0",
    "generated_by": "Person 5 (QA / Data / Integration)",
    "purpose": "Empirical evaluation corpus for future validation of the architecture-owned qualification registry and scoring system. Test cases / expected BEHAVIOR only - does not define qualification codes, claim signatures, scoring values, category caps, severity thresholds, critical floors, AI prompts, or AI adjudication logic.",
    "total_cases": len(CASES),
    "cases": CASES,
}

with open("corpus.json", "w") as f:
    json.dump(corpus, f, indent=2)

print("Wrote corpus.json")

# ---------------------------------------------------------------------------
# Coverage summary (for the README / final report)
# ---------------------------------------------------------------------------

family_counts = Counter(c["scenario_type"] for c in CASES)
confirmation_counts = Counter()
for c in CASES:
    for lvl in c["confirmation_level"]:
        confirmation_counts[lvl] += 1

source_counts = Counter()
for c in CASES:
    for s in c["source_references"]:
        source_counts[s["source"]] += 1

person3_gap_cases = [c["case_id"] for c in CASES
                      if any(s["source"] == "Person 3 parser/routing behavior" for s in c["source_references"])]

ai_relevant_cases = [c["case_id"] for c in CASES if c["ai_relevant"]]
evasion_cases = [c["case_id"] for c in CASES if c["evasion_class"]]
severity_stated_cases = [c["case_id"] for c in CASES if c["expected_severity"]]

summary = {
    "total_cases": len(CASES),
    "by_family": dict(family_counts),
    "confirmation_level_counts": dict(confirmation_counts),
    "cases_with_concept_confirmed_A": confirmation_counts.get("A", 0),
    "cases_with_exact_code_confirmed_B": confirmation_counts.get("B", 0),
    "cases_with_claim_signature_confirmed_C": confirmation_counts.get("C", 0),
    "cases_with_strength_confirmed_D": confirmation_counts.get("D", 0),
    "cases_with_scoring_direction_confirmed_E": confirmation_counts.get("E", 0),
    "source_reference_counts": dict(source_counts),
    "cases_flagged_as_person3_package_gap": person3_gap_cases,
    "cases_flagged_as_person3_package_gap_count": len(person3_gap_cases),
    "ai_relevant_case_count": len(ai_relevant_cases),
    "ai_relevant_case_ids": ai_relevant_cases,
    "evasion_case_count": len(evasion_cases),
    "evasion_case_ids": evasion_cases,
    "cases_with_a_stated_severity_direction": len(severity_stated_cases),
    "cases_with_a_stated_severity_direction_ids": severity_stated_cases,
}

with open("coverage_summary.json", "w") as f:
    json.dump(summary, f, indent=2)

print("Wrote coverage_summary.json")
print(json.dumps(summary, indent=2))
