# HopZero SECURITY_EVALUATION_CORPUS_V1

Owner: Person 5 (QA / Data / Integration)
Status: Draft for architecture-track review, prior to becoming an input to registry authoring.

## What this deliverable is / is not

**Is:** 85 test cases describing *expected system behavior* — what the parser,
deterministic analyzers, scoring engine, and AI-validation layer must or must
not do for a given input shape. Every case is traceable to a source. Unknown
values are explicitly `null`.

**Is not:** a qualification registry, a set of scoring values, a set of
claim signatures, a set of AI prompts, or an adjudication engine. No
qualification code, claim signature, strength value, or exact score is
asserted anywhere in this corpus — those fields are `null` in all 85 cases,
enforced by an automated check (see Verification below).

**Also not:** a set of built `.eml` fixture files. This pass produced the
case *specifications* (what to test and why), matching the format the task
requested. Building literal `.eml` files for all 85 cases (beyond the 11
already built in the Phase 1 corpus, which are referenced directly by case
ID where applicable) is future work once this specification itself is
reviewed — flagged explicitly under "Anything left UNKNOWN" below.

## Files in this deliverable

| File | Purpose |
|---|---|
| `corpus.json` | The 85-case machine-readable corpus |
| `coverage_summary.json` | Generated counts (family/confirmation/source breakdowns) |
| `SCHEMA.md` | Field-by-field schema documentation |
| `validate.py` | Standalone validation script (schema + boundary-discipline checks) |
| `README.md` | This file |
| `build_corpus_part1.py` … `part5.py`, `run_build.py` | Generation source, kept for traceability of how each case was authored |

## Methodology

Each case was written by:

1. Taking the exact scenario named in the task brief's numbered list (1–85).
2. Stating `expected_behavior` as system-behavior requirements, grounded in
   one of: the original architecture brief (pipeline + rules 1–10), the
   Phase 1 architecture-review corrections (CF-01…CF-06 floor definitions,
   the 18-point authentication cap), an existing Phase 1 fixture, or the
   current task brief itself.
3. Stating `expected_concepts` at the concept level only — never inventing a
   qualification code, claim signature, or exact score.
4. Recording every source used, with a `supports` letter (A–E) per the
   task's own source-discipline scheme.
5. Leaving `expected_severity` `null` unless a locked floor rule makes the
   *direction* unambiguous (e.g. "CF-02 confirmed → minimum High", or "CF-02
   explicitly NOT met, Group 2 absent"). Never an exact score or a specific
   severity label beyond that directional statement.

## PERSON 3 INTEGRATION — the one thing flagged before building anything

**Person 3's actual package (parser/security baseline tests, routing/Hop-0
tests, Evidence Normalizer tests, and the three confirmed CF-06 qualification
codes) was not shared with QA in this conversation.** The task brief
explicitly says "use the actual Person 3 package as an evidence source" and
"do not recreate his routing behavior from memory" — so family B (routing/
Hop-0, cases SEC-006 through SEC-014) and a few cross-referenced cases were
built using **only** the architecture-level CF-06 *concept* definitions
already confirmed in the Phase 1 floor review (temporal contradiction /
independent trusted contradiction / structural implausibility), never his
literal fixtures or literal code strings.

7 cases are explicitly flagged in their `source_references` with a
`Person 3 parser/routing behavior` entry whose `supports` value is
`"GAP - flagged, not confirmed"`: **SEC-006, SEC-007, SEC-008, SEC-010,
SEC-011, SEC-012, SEC-013.**

**This is the single biggest open item for architecture review**: once
Person 3's actual package is available, these 7 cases (and possibly others
in family B) should be revisited and cross-referenced against his real
fixtures/tests rather than left at the concept-only level.

## Verification performed

`validate.py` (also run as part of the build) checks, over all 85 cases:

- Every case has all 16 required schema fields.
- `expected_qualification_code`, `expected_claim_signature`,
  `expected_strength`, `expected_score` are `null` in **100% of cases (85/85)**
  — no exceptions, automatically enforced.
- `expected_behavior`, `expected_concepts`, and `source_references` are all
  non-empty in every case.
- No duplicate `case_id`.
- `confirmation_level` values are restricted to `{A, B, C, D, E}` and **never
  include B, C, or D** in this corpus (0/85 — this corpus is not authorized
  to confirm exact codes/signatures/strengths, and doesn't).
- `expected_severity` is never a bare number.

Result: **all checks pass, 0 errors.**

This is basic sanity/schema validation only — it does not run any
implementation against the corpus (none exists to run yet), per the "do not
build a production scoring engine" instruction.

## Exact numbers (from `coverage_summary.json`)

- **Total cases: 85** (matches the task brief's numbered list exactly, 1–85)
- **By family:**
  - A. Benign/Baseline — 5
  - B. Routing/Hop-0 — 9
  - C. Identity/Impersonation — 6
  - D. BEC/Content — 7
  - E. Links — 7
  - F. Domain/Lookalike — 6
  - G. Attachments — 7
  - H. Authentication — 10
  - I. Infrastructure — 5
  - J. AI H1/H2 — 9
  - K. Prompt Injection — 6
  - L. Adversarial Evasion — 8
- **Concept confirmed (A): 85 / 85** (every case has at least this)
- **Exact qualification code confirmed (B): 0 / 85**
- **Exact claim signature confirmed (C): 0 / 85**
- **Strength confirmed (D): 0 / 85**
- **Scoring direction confirmed (E): 23 / 85** — cases traceable to a locked
  CF-0x predicate outcome (met / not met) or the authentication 18-point cap,
  stated directionally, never as an exact score
- **Cases flagged as a Person 3 package gap: 7 / 85**
- **AI-relevant cases: 18 / 85** (family J entirely, most of K, three of L)
- **Adversarial-evasion cases: 9 / 85** (family L's 8, plus SEC-038 from
  family F which shares the mixed-script evasion class)
- **Source reference counts:** architecture requirement (26), explicitly
  locked AI/scoring rule (35), existing test/fixture (23), other project
  artifact (58), Person 3 parser/routing behavior (7, all flagged as gaps)
  — note a single case can cite multiple sources, so these sum to more than
  85

## Source coverage summary

Every one of the 85 cases cites at least one source; the large majority cite
two (the general architecture brief or task brief, plus a specific locked
rule or fixture where applicable). No case relies solely on QA's own
judgment with no traceable source.

## Conflicts or ambiguities found while building this corpus

These are carried forward as open questions for architecture, distinct from
(but related to) the six already raised during the Phase 1 correction pass:

1. **CF-01 scope: sender domain only, or also link/URL domain?** CF-01 as
   locked pairs a "protected-brand lookalike domain" with an explicit brand
   claim. It's unclear whether this is scoped strictly to the *sender*
   domain, or also covers a lookalike *link target* domain paired with a
   brand claim (SEC-029, SEC-032, SEC-082 all raise this).
2. **CF-03's "qualifying identity anomaly" locked predicate is still
   unknown** beyond the negative statement that a bare display-name
   mismatch doesn't satisfy it (carried over from the Phase 1 pass; affects
   SEC-015, SEC-016, SEC-017, SEC-019, SEC-031, SEC-045-adjacent cases).
3. **CF-04's "qualifying sender/security-context anomaly" locked predicate
   is still unknown** (carried over from Phase 1 fixture 06 / now also
   SEC-045).
4. **Whether multiple independently-weak identity signals can combine to
   satisfy a floor's second-condition predicate is unspecified** (SEC-019).
5. **Dedup/merge algorithm for duplicate findings with different proposed
   strengths is unspecified** beyond the behavioral requirement that
   strength must not be silently discarded (SEC-071).
6. **Whether "no DMARC record" and "DMARC evaluated with p=none policy
   result" are distinguished as separate states in the actual implementation
   is unknown** (SEC-056, echoing an ambiguity first surfaced in Phase 1
   fixture 04).

None of these were resolved unilaterally — each case states the ambiguity
explicitly in its `notes` field rather than asserting a guessed answer.

## Anything left UNKNOWN

- All `expected_qualification_code` / `expected_claim_signature` /
  `expected_strength` / `expected_score` values — by design, across all 85
  cases.
- The exact CF-06 tolerance threshold for "temporal contradiction beyond
  tolerance" (SEC-011).
- The exact structural rule(s) for "specific structural implausibility"
  (SEC-012).
- The exact definition of "independently trusted source" referenced by
  CF-06's "independent trusted contradiction" condition in the MVP, given
  rule 8 (no required external threat-intel) (SEC-013).
- Literal `.eml` fixture files for all 85 cases (only the 11 already built
  in Phase 1 exist as actual files; the remaining 74 are specified, not yet
  built as concrete email artifacts).
- Anything specific to Person 3's actual routing/Hop-0/Evidence-Normalizer
  package, per the gap flagged above.

## Anything believed to require an explicit architecture decision

1. Resolution of the six Phase 1 open questions (still outstanding as of
   this pass — see Phase 1 README) plus the six new ones listed above under
   "Conflicts or ambiguities."
2. Whether family L's evasion cases should have a formal recall-measurement
   process/metric defined at the architecture level (the task brief itself
   says the goal is "measure recall, not claim evasion-proof" — this corpus
   records the technique and base pattern per case, but the actual
   measurement methodology, e.g. how "detected" vs "not detected" gets
   scored across a run, is not something QA is deciding).
3. Whether the AI-validation family (J) behavioral invariants (SEC-063
   through SEC-071) should be formalized as a standing regression gate before
   any LLM-assisted finding is allowed to reach the scoring engine, or
   evaluated ad hoc per release — an architecture/process decision, not a
   corpus-content decision.
4. Whether/when Person 3's actual package will be made available to QA so
   family B (and the 7 flagged cases specifically) can be corrected against
   real fixtures rather than concept-only descriptions.

## What this pass did NOT do (per explicit task boundaries)

- Did not build a production scoring engine, qualification registry,
  forensic analyzers, LLM reasoner, API, database, frontend, n8n workflow,
  automatic adjudication, second-model validation, or iterative AI retries.
- Did not invent any qualification code, claim signature, strength value, or
  exact score — verified automatically (0/85 in every one of those four
  fields across the whole corpus).
- Did not recreate Person 3's routing behavior from memory — flagged as an
  explicit gap instead, on the 7 affected cases.
- Did not merge anything to GitHub.
- Did not claim anything is "verified" beyond what was actually run: the
  only verification performed is the schema/boundary-discipline check in
  `validate.py`, run against the corpus file itself — no implementation was
  tested against these cases, because none is wired up yet.
