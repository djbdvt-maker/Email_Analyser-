# SECURITY_EVALUATION_CORPUS_V1 — Schema

## Top-level structure (`corpus.json`)

```json
{
  "corpus_name": "SECURITY_EVALUATION_CORPUS_V1",
  "corpus_version": "1.0.0",
  "generated_by": "...",
  "purpose": "...",
  "total_cases": 85,
  "cases": [ ... ]
}
```

## Per-case fields

| Field | Type | Meaning |
|---|---|---|
| `case_id` | string | Stable identifier, `SEC-###`, matching the numbered case list (1–85) in the task brief. |
| `title` | string | Short human-readable name. |
| `scenario_type` | string | Case family (`A. Benign/Baseline` … `L. Adversarial Evasion`). |
| `input_description` | string | What the email/artifact under test looks like, in plain language (no literal `.eml` file is built in this pass — see "What this deliverable is / is not" in the README). |
| `expected_behavior` | array[string] | What the *system* (parser, analyzers, scoring engine, AI validator) must or must not do for this input. Behavioral statements, not implementation details. |
| `expected_concepts` | array[string] | Short concept-level tags describing the security idea being tested — **never** a registry code. |
| `expected_qualification_code` | string \| null | **Always `null` in this corpus.** No qualification code has been confirmed by an authoritative artifact for any case; none were invented. |
| `expected_claim_signature` | string \| null | **Always `null`.** Not confirmed anywhere. |
| `expected_strength` | number/string \| null | **Always `null`.** Not confirmed anywhere. |
| `expected_score` | number \| null | **Always `null`.** No exact score value is confirmed anywhere in this corpus. |
| `expected_severity` | string \| null | Only non-null where a **locked floor rule** (CF-01…CF-06, or the 18-point authentication cap) makes the *direction* unambiguous — e.g. `"minimum High (CF-02 confirmed)"` or `"CF-01 explicitly NOT met (Group 2 absent)"`. This is a directional/boundary statement, never an exact severity label or score. |
| `ai_relevant` | boolean | Whether this case exercises the semantic/LLM analysis path. |
| `evasion_class` | string \| null | The specific adversarial technique being tested (family L), else `null`. |
| `notes` | string | Cross-references, open questions, caveats. |
| `source_references` | array[object] | Where each expected behavior came from — see below. Never empty. |
| `confirmation_level` | array[string] | Subset of `["A","B","C","D","E"]` — see below. This corpus contains **only `A` and `E`** values; `B`, `C`, `D` never appear (enforced by the build script's sanity check). |

## `source_references[]` object

```json
{ "source": "...", "reference": "...", "supports": "A" }
```

- `source` — category (`architecture requirement`, `explicitly locked AI/scoring rule`, `existing test/fixture`, `other project artifact`, `Person 3 parser/routing behavior`).
- `reference` — the specific document/message/fixture being pointed at.
- `supports` — which confirmation letter (A–E) this source backs for this case.

## Confirmation-level letters (per the task brief's source discipline)

| Letter | Meaning | Used in this corpus? |
|---|---|---|
| A | Behavior/concept confirmed | Yes — every case has at least A. |
| B | Exact qualification code confirmed | **Never** — no code has been confirmed to QA; none invented. |
| C | Exact claim signature confirmed | **Never**. |
| D | Strength confirmed | **Never**. |
| E | Scoring *direction* confirmed (floor triggers / does not trigger — not an exact score) | 23 cases, all traceable to a locked CF-0x predicate or the 18-point auth cap. |

## Special value: `"GAP - flagged, not confirmed"` (in `source_references[].supports`)

Used only for the `Person 3 parser/routing behavior` source, on the 7 cases (SEC-006, 007, 008, 010, 011, 012, 013) that would ideally be grounded in Person 3's actual routing/Hop-0/Evidence-Normalizer package. That package was not available to QA in this conversation; these cases are built from the architecture-level CF-06 concept definitions only. See README "Gaps" section.

## Files in this deliverable

- `corpus.json` — the 85-case machine-readable corpus (this schema).
- `coverage_summary.json` — generated counts (family breakdown, confirmation-level counts, source counts, gap list, AI-relevant list, evasion list).
- `README.md` — human-readable overview, methodology, and the required report items.
- `validate.py` — standalone script re-running the same sanity checks the build performed (schema conformance, uniqueness, boundary discipline, non-empty required fields).
- `build_corpus_part1.py` … `part5.py`, `run_build.py` — the generation source itself, kept for traceability/auditability of how each case's content was produced.
