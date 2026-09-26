# Implementation Notes (V3 baseline)

**V4 update:** see `V4_CHANGELOG.md` for the AI trust boundary and
backend Score Engine work, and for the current, restated status of the
audit trigger and export-hash items below (a couple of claims in this
V3 file were more confident than they should have been; V4_CHANGELOG.md
corrects that). Everything below that ISN'T about scoring/AI candidates
is still accurate and wasn't touched in the V4 pass.

**V4.1 update:** see `V4_1_CHANGELOG.md` for the full implementation
pass that resolved all stubbed components, eliminated placeholder
values, added the conclusion generator, async analysis pipeline,
role enforcement, evidence export bundles, and frontend truthfulness
fixes. The test suite (253 tests) has been confirmed passing.

## Important: execution environment caveat

The sandbox this backend was produced in has **no network access**, so
`pip install` cannot fetch FastAPI/SQLAlchemy/Alembic/psycopg2/pytest,
and there is no local PostgreSQL server available to run against.
That means:

- I could **not** run `pytest`, start `uvicorn`, or run
  `alembic upgrade head` in this environment.
- I **did** run `python -m py_compile` over every file in `app/`,
  `alembic/`, and `tests/`, which confirms the code is syntactically
  valid Python and catches typos/indentation/import-path mistakes at
  the parse level. It does **not** confirm the tests pass, that
  SQLAlchemy mappings are internally consistent, or that the FastAPI
  app boots.
- Please run `pip install -r requirements.txt && pytest -v` yourself
  before merging. I've written the test suite to be genuinely useful
  once that's done, but I have not personally seen it go green, and
  saying otherwise would be dishonest. This is the single biggest
  thing to verify before treating this as production-ready.

Everything below describes what the code is *intended* to do and
where I made judgment calls, not a report of a verified test run.

## Status legend

- **IMPLEMENTED** -- code exists and is intended to be complete for MVP scope.
- **STUBBED** -- a real interface/contract exists but the underlying logic is intentionally not implemented here (belongs to a different component).
- **NOT IMPLEMENTED** -- not attempted in this delivery.

## By requirement

| Area | Status | Notes |
|---|---|---|
| FastAPI app + `/api/v1` routes | IMPLEMENTED | `app/main.py`, `app/api/v1/*` |
| PostgreSQL persistence | IMPLEMENTED (untested against real Postgres) | Models use only cross-dialect column types; Alembic migration targets Postgres explicitly |
| SQLAlchemy models | IMPLEMENTED | `app/models.py` |
| Pydantic schemas | IMPLEMENTED | `app/schemas.py` |
| Alembic migrations | IMPLEMENTED (not run against a live DB) | Single hand-written initial migration, `alembic/versions/0001_initial.py`. Not generated via `--autogenerate` since no DB was reachable to diff against. |
| Investigation lifecycle | IMPLEMENTED | `app/services/investigation_service.py`; explicit transition table, `reopen` is an action not a status |
| AnalysisRun lifecycle | IMPLEMENTED | `app/services/analysis_run_service.py`; `current_analysis_run_id` only ever set on COMPLETED, never by failed/cancelled runs, no `set_current_run` action exists |
| Artifact ingestion + SHA-256/MD5 | IMPLEMENTED | `app/services/evidence_service.py`; hashes computed over the exact bytes written to disk |
| Persistent artifact storage abstraction | IMPLEMENTED (local filesystem only) | `ARTIFACT_STORAGE_ROOT`; swapping to S3/object storage would mean changing this one module |
| Fact/Finding persistence with locked contracts | IMPLEMENTED | `app/services/fact_service.py`, `app/services/finding_service.py` |
| Finding dedup (category+qualification_code+claim_signature+target) | IMPLEMENTED | Enforced by a DB unique constraint plus service-layer merge logic; strength is never recomputed or upgraded on merge |
| AI-candidate trust boundary (qualification/claim_signature validation, deterministic strength rules) | SUPERSEDED | Now IMPLEMENTED in V4 — see `V4_CHANGELOG.md`. (Row kept for history; the V3 "out of scope" call was correct for V3's architecture message, explicitly reversed in V4's.) |
| Score Engine | SUPERSEDED | Now IMPLEMENTED in V4, backend-owned, not an external interface — see `V4_CHANGELOG.md`. |
| Conclusion Generator | SUPERSEDED | V3: `app/interfaces/conclusion_generator.py` (stub only); V4.1: **IMPLEMENTED** as `app/services/conclusion_generator.py` — deterministic rule/template-based, produces structured `ConclusionOutput(verdict, one_line_explanation, why_explanation)` |
| Score/Conclusion validation + persistence | SUPERSEDED | V3's caller-supplied `/score-conclusion` endpoint and `score_conclusion_service.py` have been **deleted** in V4 and replaced with a compute-only Score Engine — see `V4_CHANGELOG.md`. |
| Server-side auth/org scoping | IMPLEMENTED | JWT via `app/security.py`; every service function re-checks `organization_id` server-side (never trusts a client-supplied org id) |
| Investigation actions (status transitions, reopen) | IMPLEMENTED | see lifecycle notes above |
| Append-only audit events | IMPLEMENTED at the code layer; Postgres trigger IMPLEMENTED but unverified | No route/service ever issues UPDATE/DELETE against `audit_events`. The Alembic migration also adds a Postgres trigger that rejects such statements at the DB layer, guarded by a dialect check so it's a no-op under SQLite tests. I could not verify the trigger actually fires, since no Postgres instance was reachable. |
| API error handling | IMPLEMENTED | Structured `{error_code, message, details}` JSON via exception handlers in `app/main.py` |
| Tests | IMPLEMENTED (not run) | See caveat above. Covers investigation/run lifecycles, org scoping, evidence retrieval-vs-export audit separation, finding dedup/no-strength-upgrade, and score/conclusion validation. |
| Docker/Compose | IMPLEMENTED (not run — no Docker daemon in this environment either) | `Dockerfile`, `docker-compose.yml` |

## Deliberate scope exclusions (per architecture message)

Not implemented, and not intended to be implemented in this package:

- Forensic detection logic, Hop-0/SPF/DKIM/DMARC analysis, URL/domain/attachment analysis
- LLM semantic reasoning
- Scoring mathematics, category caps, severity thresholds, risk floor predicates
- Independent verdict logic
- Microservices, message brokers, Kubernetes
- A public self-signup endpoint (users are provisioned via `scripts/create_user.py`; add a real signup/invite flow later if the product needs it)

## Judgment calls worth flagging

- **User provisioning**: no signup endpoint was specified, so I added
  an operator-run bootstrap script instead of inventing an
  unauthenticated `/signup` route.
- **Investigation status transition table**: the corrections doc fixed
  the status *set* but didn't fully specify every legal transition. I
  implemented a conservative forward-only state machine (see
  `_ALLOWED_TRANSITIONS` in `investigation_service.py`) plus the
  `reopen` action; this is the kind of thing worth a quick sanity
  check against product expectations before shipping.
- **Finding strength conflict on merge**: when a dedup collision
  arrives with a *different* `strength` than the existing Finding, I
  keep the original value and record the conflict in the audit event
  metadata (`strength_conflict`, `kept_strength`, `incoming_strength`)
  rather than silently picking the higher one. This satisfies "no
  auto-upgrade" but the exact reconciliation policy (keep first? flag
  for manual review? something else?) wasn't specified and is worth
  confirming.
- **Score/Conclusion validation depth**: I validate severity bucket
  names, score range, and that `provenance.score_engine_version` is
  present, but I do not know the Score Engine's real payload shape
  since that component doesn't exist yet in this delivery. Treat
  `ScoreConclusionIn` as a reasonable placeholder contract, not a
  finalized one.
- **Alembic migration was hand-written**, not autogenerated, since no
  database was reachable to diff against. Worth running
  `alembic check` / a real `--autogenerate` diff once Postgres is
  available to catch anything hand-writing missed.

## Issues caught and fixed during self-review (before packaging)

Since I couldn't run the code, I did a manual second pass instead and
found two real bugs, fixed here:

1. **Circular FK dependency**: `Investigation.current_analysis_run_id`
   references `analysis_runs.id`, and `AnalysisRun.investigation_id`
   references `investigations.id` -- a genuine circular dependency
   between the two tables. Without `use_alter=True` on the first FK,
   `Base.metadata.create_all()` (used by the test suite) would raise
   `CircularDependencyError`. Fixed in `app/models.py`; the hand-written
   Alembic migration already handled this correctly via a deferred
   `op.create_foreign_key` call, so only the model definition needed
   the fix.
2. **Path/resource consistency gap**: `GET/POST` routes under
   `/investigations/{investigation_id}/analysis-runs/{run_id}` only
   validated organization ownership of the run, not that the run
   actually belongs to the `investigation_id` in the path -- so a
   request naming the wrong (but same-org) investigation ID alongside
   a real run ID would have silently succeeded. Not a cross-org
   security hole, but wrong REST semantics. Fixed by threading
   `investigation_id` through `get_analysis_run` /
   `transition_run_status` and added
   `test_run_id_must_belong_to_path_investigation` to cover it.

I flag these explicitly rather than silently folding them in, since I
can't rule out that a similar class of bug exists elsewhere and wasn't
caught by static review alone -- another reason to actually run the
test suite before merging.

## Anything still unresolved

- ~~Whether the Score Engine and Conclusion Generator will be
  in-process Python calls or HTTP calls to a separate service is not
  yet decided~~ **RESOLVED in V4.1:** Both are in-process Python calls.
  The `ConclusionGenerator` is integrated directly into `score_engine.py`
  and the `ScoreEngineService` orchestrates persistence. No external
  service dependencies.
- Rate limiting, pagination, and multi-tenant admin tooling are not
  addressed -- reasonable for MVP scope, but flagging since they
  weren't explicitly discussed either way.
- The Postgres append-only trigger on `audit_events` remains unverified
  against a real PostgreSQL instance (test suite runs against SQLite).
