# V4 Changelog — AI Trust Boundary + Backend Score Engine

## Execution caveat (read this first)

This sandbox has no network access. I confirmed this again in this
session by attempting `pip install fastapi` and getting
`No matching distribution found`. There is also no PostgreSQL server
reachable. As a result:

- **I did not run `pytest`.** I cannot give you a real pass/fail count.
- **I did not start `uvicorn` or run `alembic upgrade head`.**
- **What I did do:** run `python -m py_compile` over every `.py` file
  in `app/`, `alembic/`, `tests/`, and `scripts/` after every edit.
  This confirms the code is syntactically valid and that imports
  resolve at the parse level (no typos in module paths, no
  indentation errors). It does **not** confirm the SQLAlchemy mappings
  are internally consistent, that FastAPI's dependency injection wires
  up correctly, or that any test actually passes.

**Test command to run yourself:**
```bash
pip install -r requirements.txt
pytest -v
```

**Test count:** 65 test functions across 10 files (`grep -rE "^def test_" tests/*.py | wc -l`).
This is a count of what I wrote, not a report of what passed. Please
run the command above and tell me what you get — if anything fails,
paste the output and I'll fix the actual bug rather than the number.

---

## P0 fixes

| # | Requirement | Status | Where |
|---|---|---|---|
| P0-1 | Backend enforces the AI→Finding trust boundary | **IMPLEMENTED** | `app/services/trust_boundary_service.py` |
| P0-2 | FACT / AICANDIDATE / FINDINGCANDIDATE / FINDING ontology preserved | **IMPLEMENTED** | `AICandidate` and `Fact` are separate tables (`app/models.py`); `FindingCandidate` is a transient dataclass (`_FindingCandidate` in `trust_boundary_service.py`), never persisted, never confused with a `Fact` |
| P0-3 | Qualification registry validation (exists, AI-eligible, claim_signature permitted, grounding, validity, strength) | **IMPLEMENTED** | `app/qualification_registry.py` (data) + `trust_boundary_service._validate_candidate` (pipeline) |
| P0-4 | AI-eligibility structurally enforced, contradictory entries rejected | **IMPLEMENTED** | `qualification_registry._validate_entry`, run at **import time** over every registry entry; unit-tested directly in `tests/test_registry_validation.py` against hand-built bad entries (not just the shipped registry, which is already valid) |
| P0-5 | H2 semantic validity is a hard gate, no Weak/Moderate fallback | **IMPLEMENTED, WITH DOCUMENTED SCOPE LIMIT** | `app/services/validity_engine.py::check_h2_semantic_validity`. Correctly rejects the exact corrections-doc example (verified by tracing the logic; not by running the test). See "H2 gate scope" below. |
| P0-6 | Validity requirements are local to the claim only | **IMPLEMENTED** | Every predicate in `validity_engine.py` takes only `(window, supporting_text)` — the local sentence window and the grounded span. No predicate anywhere takes a `Finding` list or looks at other categories. Passes the doc's isolation test by construction. |
| P0-7 | supporting_text not restricted to one sentence; no iterative LLM retry on validity failure | **IMPLEMENTED** | Grounding (`check_grounding`) matches any contiguous substring, not a single-sentence regex. The H2 window is derived for gating purposes only, not as a length restriction on `supporting_text` itself. There is no retry path anywhere — a validity failure returns `_Rejected` and stops. |
| P0-8 | Strength is deterministic; model_suggested_strength is telemetry only | **IMPLEMENTED** | `trust_boundary_service._validate_candidate` computes `strength` purely from `entry.default_strength` + `entry.strength_rules` predicates; `payload.model_suggested_strength` is stored on the `AICandidate` row and never read anywhere else in the codebase (`grep -rn model_suggested_strength app/` shows it appears only in `models.py`, `schemas.py`, and the one place it's *stored* in `trust_boundary_service.py` — never in a conditional that affects `strength`) |
| P0-9 | Backend owns the deterministic Score Engine | **IMPLEMENTED** | `app/services/score_engine.py` (pure functions, no DB access) + `app/services/floor_engine.py` + `app/services/score_engine_service.py` (orchestration/persistence). The old `app/interfaces/score_engine.py` external-interface stub is explicitly marked superseded and now exports nothing. |
| P0-10 | Locked scoring constants (Weak=8, Moderate=18, Strong=30) | **IMPLEMENTED** | `score_engine.STRENGTH_POINTS`; unit-tested in `test_score_engine.py::test_strength_point_constants_locked` |
| P0-11 | Locked category caps | **IMPLEMENTED** | `score_engine.CATEGORY_CAPS`; unit-tested; "clean Authentication" tested explicitly to contribute exactly 0, never negative |
| P0-12 | Floors implemented separately from scoring, only on validated Findings | **IMPLEMENTED, WITH ONE GAP (CF-01) AND ONE SIMPLIFICATION (CF-06)** | `app/services/floor_engine.py`. See "Floor scope" below for CF-01/CF-06 detail. |
| P0-13 | Finding schema fields | **IMPLEMENTED (unchanged from V3)** | `app/models.py::Finding` already had every required field; V4 did not need to change this table's shape, only how strength gets into it |
| P0-14 | Dedup key + no auto-upgrade on merge | **IMPLEMENTED (unchanged from V3)** | `app/services/finding_service.py`; V4 added a second entry point (`persist_finding_from_trust_boundary`) that reuses the exact same dedup/merge core (`_persist_or_merge`), so the "no auto-upgrade" guarantee applies identically to AI-derived and deterministic Findings |
| P0-15 | Score API cannot accept a caller-supplied score/severity/floors | **IMPLEMENTED** | `POST /investigations/{id}/analysis-runs/{run_id}/score` takes **no request body at all** (see `app/api/v1/routes_findings.py::compute_score` — no `body:` parameter). The old `ScoreConclusionIn` schema that accepted these values from a caller has been **deleted**, not just deprecated. |

## P1 fixes

| # | Requirement | Status | Where |
|---|---|---|---|
| Registry/version provenance on AnalysisRun | **IMPLEMENTED** | `AIExecutionProvenance.qualification_registry_version` / `.validity_rule_version`, pinned from the registry module's current constants at the moment the AI execution is recorded (not re-resolved later); `Finding.qualification_version` continues to be set from the registry entry's `.version` |
| AI execution provenance tuple (exact fields) | **IMPLEMENTED** | `AIExecutionProvenance` model has exactly: `model_identifier`, `model_version_or_digest`, `prompt_schema_version`, `qualification_registry_version`, `validity_rule_version`, `deterministic_context_snapshot_hash`, `ai_generation_parameters` (JSON blob for temperature/top_p/top_k/seed/max_tokens/etc). 1:1 with AnalysisRun via a unique FK; no update/delete code path exists for it. |
| current_analysis_run_id semantics preserved | **IMPLEMENTED (unchanged from V3)** | `app/services/analysis_run_service.py` — not touched in this pass |
| Investigation lifecycle preserved (no REOPENED status) | **IMPLEMENTED (unchanged from V3)** | `app/services/investigation_service.py` — not touched in this pass |
| Evidence/audit architecture preserved | **IMPLEMENTED (unchanged from V3), WITH A HONESTY CORRECTION** | See "Corrections to prior claims" below — I was too confident about the Postgres trigger and export hash in the V3 delivery; restating the accurate status here. |
| Audit immutability (app-level + DB-level) | **IMPLEMENTED at app level; DB trigger IMPLEMENTED but UNVERIFIED** | See below |

---

## Corrections to prior claims (per your explicit instruction not to fabricate)

You're right to call this out specifically. Restating precisely, with
no upgrade in confidence from before:

- **Postgres append-only trigger on `audit_events`**: the trigger DDL
  exists in `alembic/versions/0001_initial.py`, guarded by a
  `dialect.name == "postgresql"` check. It has never been run against
  a real PostgreSQL instance in any session of this project. I am not
  claiming it "works," only that the DDL is written and, as far as I
  can trace by reading it, looks correct. **This needs a real
  integration test against actual Postgres before anyone relies on
  it.** I have not added that integration test — it requires a live
  Postgres connection I don't have here, and I'm flagging that as
  **DEFERRED**, not silently skipping it.
- **`export_bundle_sha256`**: in the current implementation
  (`app/services/evidence_service.py::export_artifact`), this hash is
  computed over the *same original artifact bytes* as
  `original_artifact_sha256` — there is no actual "bundle" (e.g. a
  zip with metadata/audit trail attached) being built yet. The two
  fields are architecturally distinct (separate columns, separate
  computation call sites) but currently produce the same value for
  the same artifact. This was already noted in V3's
  `IMPLEMENTATION_NOTES.md` and remains true and unchanged in V4. I am
  restating it here rather than letting it go unmentioned in this
  handoff.
- **"Person 5 QA corpus" / "frozen deliverables"**: I have not been
  given this corpus and have not touched anything claiming to be it.
  I have no way to verify its existence or contents from here, so I'm
  not asserting anything about it either way.

---

## H2 gate scope (validity_engine.py)

The H2 gate is a **local disqualifier-phrase lexicon check**, not
general natural-language understanding. Concretely:

1. It finds the sentence containing the grounded `supporting_text` span.
2. It checks whether that sentence contains one of a fixed list of
   disqualifying phrases (e.g. "testing whether", "security awareness",
   "this is a test", "phishing simulation").
3. If yes → REJECTED. If no → passes to strength-rule evaluation.

This **does** correctly reject the exact corrections-doc example
("The security team is testing whether employees can recognize
requests to transfer funds.") because "testing whether" is in the
list and shares a sentence with the grounded span.

This **does not** generalize to arbitrarily-phrased context-stripping.
A sentence that strips the same meaning without using one of these
phrases (e.g. "Someone asked me to explain what a request to transfer
funds looks like") would **not** be caught by this version. Extending
this list is expected, ongoing, versioned work — that's the entire
point of `VALIDITY_RULE_VERSION` existing as a separate version from
`REGISTRY_VERSION`. I am not claiming this solves H2 in general.

## Floor scope (floor_engine.py)

- **CF-01** (protected-brand lookalike domain + explicit brand claim):
  **NOT IMPLEMENTED.** It requires a second qualification representing
  "explicit claim representing that brand" that doesn't exist yet in
  the starter registry. I chose not to invent one just to check a box
  — adding a qualification that doesn't correspond to anything real
  the (nonexistent, in this delivery) forensics/AI components actually
  produce would be worse than leaving a documented gap.
- **CF-06** (qualified routing fabrication): **IMPLEMENTED AS A
  SIMPLIFICATION.** The doc restricts CF-06 to "temporal contradiction
  beyond tolerance / independent trusted contradiction / specific
  structural implausibility" and excludes generic malformed routing.
  I did not implement those three as separate deterministic
  sub-predicates. The floor engine currently just checks "is there a
  Moderate+ `ROUTING_FABRICATION_QUALIFIED` Finding" and assumes that
  qualification's own (not-yet-implemented, since no forensics
  component exists in this delivery to produce it) strength rules
  already encode that distinction upstream. This is a real gap, not a
  documentation nicety — flagging it as **DEFERRED**.
- **CF-02, CF-03, CF-04, CF-05**: implemented as written, each as an
  AND of qualification-code + minimum-strength requirements.

## Registry scope

The qualification registry (`app/qualification_registry.py`) has 9
entries — enough to exercise every implemented floor and the H2
example, not a production-complete set. `normalized_subject_or_target`
for AI-derived Findings is currently set to `claim_signature` itself
(see `trust_boundary_service._validate_candidate`) as a placeholder —
there's no real entity-extraction/normalization (e.g. resolving to a
canonical sender address or amount) in this delivery. This is a
simplification worth flagging, not a finished design decision.

---

## Files changed in this pass

**New:**
- `app/qualification_registry.py`
- `app/services/validity_engine.py`
- `app/services/floor_engine.py`
- `app/services/score_engine.py`
- `app/services/score_engine_service.py` (replaces deleted `score_conclusion_service.py`)
- `app/services/ai_execution_service.py`
- `app/services/trust_boundary_service.py`
- `app/api/v1/routes_ai.py`
- `alembic/versions/0002_v4_trust_boundary_and_score_engine.py`
- `tests/test_ai_trust_boundary.py`, `tests/test_registry_validation.py`, `tests/test_score_engine.py`, `tests/test_floors.py`

**Modified:**
- `app/models.py` — added `AIExecutionProvenance`, `AICandidate`, `AICandidateStatus`; added 3 `AuditAction` members; `ScoreConclusion` gained `category_breakdown`, lost nothing
- `app/schemas.py` — added AI-execution/candidate schemas + `ScoreOut`; **deleted** `ScoreConclusionIn`/`ScoreConclusionOut`
- `app/services/finding_service.py` — added `DETERMINISTIC_PRODUCERS` allow-list check on the public path; split into `persist_finding` (public, checked) vs `persist_finding_from_trust_boundary` (internal, used only by the trust boundary) vs shared `_persist_or_merge` core
- `app/api/v1/routes_findings.py` — removed the old caller-supplied `/score-conclusion` endpoint; added compute-only `/score` endpoints
- `app/main.py` — registered `routes_ai`, updated app description/version
- `app/interfaces/score_engine.py` — gutted to a "superseded" pointer
- `README.md` — rewritten for V4 endpoints/architecture

**Deleted:**
- `app/services/score_conclusion_service.py`
- `tests/test_score_conclusion.py` (tested the now-deleted caller-supplied contract)

---

## Known limitation: two-step commit between Finding and AICandidate audit row

`trust_boundary_service.submit_ai_candidate` calls
`persist_finding_from_trust_boundary` (which commits internally when it
creates/merges a Finding), and *then* separately inserts and commits
the `AICandidate` audit row. These are two separate transactions, not
one atomic unit. If the process crashed between them, you could end up
with a Finding that has no corresponding `AICandidate` audit record.
This is a real gap I noticed while reviewing my own code, not
something I'm papering over — fixing it properly would mean
restructuring `finding_service` to not commit internally and instead
let the caller control the transaction boundary. I left it as-is for
this delivery scope and am flagging it as **DEFERRED**.

## Architectural questions that remain

1. Should `AIExecutionProvenance` really be 1:1 with `AnalysisRun`, or
   1:1 with a single model *call* (allowing multiple AI executions per
   run for different qualification categories)? I implemented 1:1 with
   `AnalysisRun` per my reading of "a retry is a new AnalysisRun," but
   the doc doesn't explicitly rule out multiple executions per run.
2. Whether `normalized_subject_or_target` needs real entity
   normalization (sender address, amount, domain) before this is
   usable for genuine dedup quality, versus the current
   claim_signature placeholder.
3. Whether CF-01 and the CF-06 sub-predicates block V4 sign-off or can
   ship as documented gaps for a V5 pass — I don't have enough context
   on your review process to guess at this.
