# HopZero Backend

FastAPI backend implementing the locked HopZero V4.2 hardened architecture:
Investigation/AnalysisRun lifecycle (with strict completed-only current run semantics),
evidence ingestion, the AI candidate trust boundary, Fact/Finding persistence with locked
dedup semantics, a backend-owned deterministic Score Engine (points, category caps,
critical-risk floors, severity -- strictly numeric, no verdicts), deterministic Conclusion
Generator (evidence-grounded verdicts and explanations only), async analysis pipeline,
and role-based access control with canonical analyst actions.

**This component does NOT implement:** forensic detection logic,
Hop-0/SPF/DKIM/DMARC analysis, URL/domain/attachment analysis, or the
LLM itself. It DOES implement the deterministic boundary around AI
output (registry validation, grounding, the H2 semantic gate,
deterministic strength rules) and the deterministic Score Engine
(points, caps, floors, severity) -- as of V4 these are backend-owned,
not external interfaces. See `V4_CHANGELOG.md` for exactly what
changed and why, and for scope limitations of the H2 gate and the
starter qualification registry.

## Requirements

- Python 3.11+
- PostgreSQL 14+ (for production; the test suite uses SQLite so it has
  no external dependency)
- Docker + Docker Compose (optional, for the containerized stack)

## Local setup (without Docker)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env with your local Postgres connection string

# Start Postgres however you like, then:
alembic upgrade head

# Create a first user (there is no public signup endpoint by design):
python scripts/create_user.py --org-name "Acme Security" \
    --email analyst@acme.test --password "changeme123" --role ADMIN

uvicorn app.main:app --reload
```

Visit `http://localhost:8000/docs` for interactive OpenAPI docs.

## Docker Compose

```bash
docker compose up --build
# in another shell, once the backend is healthy:
docker compose exec backend python scripts/create_user.py \
    --org-name "Acme Security" --email analyst@acme.test \
    --password "changeme123" --role ADMIN
```

## Running tests

```bash
pip install -r requirements.txt
pytest -v
```

Tests run against an in-memory SQLite database via `tests/conftest.py`
and do not require Postgres or Docker. **Hardened V4.2:** 276 tests confirmed
passing across all 5 test suites (01_REGISTRY: 2, 02_FORENSICS: 99, 03_BACKEND: 154,
05_QA: 17, 06_N8N: 4).

## API usage examples

Authenticate:

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -d "username=analyst@acme.test&password=changeme123"
# => {"access_token": "...", "token_type": "bearer"}
```

Create an investigation and a run:

```bash
curl -X POST http://localhost:8000/api/v1/investigations \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"title": "Suspicious wire transfer email"}'

curl -X POST http://localhost:8000/api/v1/investigations/$INV_ID/analysis-runs \
  -H "Authorization: Bearer $TOKEN"
```

Upload evidence, then retrieve vs. export (two distinct operations):

```bash
curl -X POST http://localhost:8000/api/v1/investigations/$INV_ID/evidence \
  -H "Authorization: Bearer $TOKEN" -F "file=@sample.eml"

# Read-only, no audit event:
curl http://localhost:8000/api/v1/investigations/$INV_ID/evidence \
  -H "Authorization: Bearer $TOKEN"

# Explicit export, generates EVIDENCE_EXPORTED audit event:
curl -X POST http://localhost:8000/api/v1/investigations/$INV_ID/evidence/$ARTIFACT_ID/export \
  -H "Authorization: Bearer $TOKEN"
```

Record a Fact (deterministic observation -- e.g. the raw email body
text the AI trust boundary will ground against):

```bash
curl -X POST http://localhost:8000/api/v1/investigations/$INV_ID/facts \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "analysis_run_id": "'$RUN_ID'",
    "fact_type": "raw_source_text",
    "payload": {"text": "Please wire $5,000 to account 123456789 today."},
    "produced_by": "forensics_parser_v1"
  }'
```

**The AI trust boundary** -- record an AI execution once per run, then
submit AI candidates against it. Only ACCEPTED candidates ever create
or merge a Finding, with strength computed deterministically (never
from `model_suggested_strength`):

```bash
curl -X POST http://localhost:8000/api/v1/investigations/$INV_ID/analysis-runs/$RUN_ID/ai-execution \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "model_identifier": "claude-example",
    "model_version_or_digest": "sha256:...",
    "prompt_schema_version": "prompt-v1",
    "deterministic_context_snapshot_hash": "sha256:...",
    "ai_generation_parameters": {"temperature": 0.0}
  }'

curl -X POST http://localhost:8000/api/v1/investigations/$INV_ID/analysis-runs/$RUN_ID/ai-candidates \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "qualification_code": "FINANCIAL_REQUEST",
    "claim_signature": "payment_transfer_request",
    "supporting_text": "wire $5,000 to account 123456789",
    "source_fact_id": "'$FACT_ID'",
    "model_suggested_strength": "Strong",
    "produced_by": "ai_reasoner"
  }'
```

A trusted deterministic producer (e.g. hopzero-forensics) may instead
submit a Finding directly. This requires BOTH a valid user JWT **and**
the `X-Internal-Service-Key` header (set via `HOPZERO_INTERNAL_SERVICE_KEY`
in your `.env` -- there is no fallback/default value, so this endpoint
is unavailable until you configure one):

```bash
curl -X POST http://localhost:8000/api/v1/investigations/$INV_ID/findings \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Internal-Service-Key: $HOPZERO_INTERNAL_SERVICE_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "category": "Identity",
    "qualification_code": "IDENTITY_ANOMALY",
    "qualification_version": "reg-v1",
    "strength": "Moderate",
    "normalized_subject_or_target": "sender-identity",
    "claim_signature": "sender_identity_anomaly",
    "supporting_fact_ids": ["fact-1"],
    "supporting_text": "SPF/DKIM/DMARC alignment failure detected.",
    "produced_by": "deterministic"
  }'
```

Compute the score once the run reaches SCORING/COMPLETED -- there is
no request body, and no way to supply the score yourself:

```bash
curl -X POST http://localhost:8000/api/v1/investigations/$INV_ID/analysis-runs/$RUN_ID/score \
  -H "Authorization: Bearer $TOKEN"
```

### V4.1 endpoints

Upload an artifact (e.g. `.eml` file) and start async analysis:

```bash
# Upload artifact
curl -X POST http://localhost:8000/api/v1/investigations/$INV_ID/artifacts \
  -H "Authorization: Bearer $TOKEN" -F "file=@suspicious_email.eml"

# Start async analysis (returns 202)
curl -X POST http://localhost:8000/api/v1/investigations/$INV_ID/analyze \
  -H "Authorization: Bearer $TOKEN"
# => {"investigation_id": "...", "analysis_run_id": "...", "status": "QUEUED"}
```

Perform a canonical analyst action:
- `confirm_malicious`: Mark confirmed threat (requires ANALYST / ADMIN)
- `false_positive`: Mark false positive with required rationale (requires ANALYST / ADMIN)
- `needs_escalation`: Escalate to senior tier (requires ANALYST / ADMIN)
- `add_note`: Add analyst note, logs NOTE_ADDED audit event (permitted for all authenticated org users; does not mutate status)
- `reopen`: Reopen closed/resolved investigation back to UNDER_REVIEW (requires ANALYST / ADMIN; does not create AnalysisRun)
- `close`: Close investigation (requires ANALYST / ADMIN)

*Note: Legacy aliases (`CONFIRM`, `CONFIRM_MALICIOUS`, `MARK_FALSE_POSITIVE`, `ESCALATE`, `NOTE`) are rejected with HTTP 422.*

```bash
# Add analyst note (generates NOTE_ADDED audit event):
curl -X POST http://localhost:8000/api/v1/investigations/$INV_ID/actions \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"action": "add_note", "note": "Reviewing SPF/DKIM headers manually"}'

# Confirm threat:
curl -X POST http://localhost:8000/api/v1/investigations/$INV_ID/actions \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"action": "confirm_malicious", "note": "Verified phishing attempt"}'
```

View the audit trail:

```bash
curl http://localhost:8000/api/v1/investigations/$INV_ID/audit \
  -H "Authorization: Bearer $TOKEN"
```

## Architecture & Lifecycle Notes

- **InvestigationStatus Lifecycle**: Canonical statuses are strictly `AWAITING_ANALYSIS`, `UNDER_REVIEW`, `CONFIRMED`, `FALSE_POSITIVE`, `ESCALATED`, `CLOSED`. The redundant `ANALYZED` state has been eliminated. Automated analysis completion transitions an investigation directly from `AWAITING_ANALYSIS` to `UNDER_REVIEW`. A new analysis run never silently overwrites an existing human disposition (`CONFIRMED`, `FALSE_POSITIVE`, `ESCALATED`, `CLOSED`).
- **AnalysisRun Lifecycle**: Explicitly `QUEUED`, `PARSING`, `ANALYZING`, `SCORING`, `COMPLETED`, `FAILED`, `CANCELLED`.
- **Current Analysis Run Pointer**: `investigation.current_analysis_run_id` points **strictly** to the latest usable `COMPLETED` run. Queued, parsing, running, failed, or cancelled runs never overwrite it.
- **Score Engine vs. Conclusion Generator**: The Score Engine computes *only* numeric scoring (score, category breakdown, floor codes, severity). The Conclusion Generator is invoked separately by the orchestration layer to produce evidence-grounded verdicts and explanations.
- **Forensics Routing Fabrications (CF-06)**: Subtypes are strictly bounded:
  - `CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE` (Q39): Pairwise hops with negative transit time beyond the 5-minute tolerance window.
  - `CF-06:INDEPENDENT_TRUSTED_CONTRADICTION` (Q40): An untrusted hop claims routing path from a trusted host, while observed transmission infrastructure contradicts the verified infrastructure of the trusted provider. Missing headers, unknown relays, external IPs, generic malformedness, and auth failures do NOT satisfy Q40 (`UNKNOWN ≠ CONTRADICTORY`).
  - `CF-06:STRUCTURAL_IMPLAUSIBILITY` (Q41): Cross-provider identity break detection strictly within the contiguous trusted receiving boundary (`boundary_index >= 1`).
- **Server-Side Role Authorization**: All state-changing actions (`confirm_malicious`, `false_positive`, `needs_escalation`, `reopen`, `close`) require `ANALYST` or `ADMIN` role. Unauthorized callers receive HTTP 403. Tenant isolation is strictly enforced (cross-organization requests receive HTTP 404).
- **Audit Model & Frontend Classification**: Uses `INVESTIGATION_STATUS_CHANGED`, `NOTE_ADDED`, `INVESTIGATION_REOPENED`, etc. Frontend audit classifier maps status transitions with `to = CONFIRMED` to `confirmation`, `to = ESCALATED` to `escalation`, `to = CLOSED` to `close`, `NOTE_ADDED` to `note`, and `INVESTIGATION_REOPENED` to `reopen`.
- **Async Execution**: The async pipeline runs in-process via daemon threads (`threading.Thread`) for lightweight, standalone MVP deployment. Durable message queues (Celery/Redis) represent a future production scaling path.

## Project layout

```
app/
  main.py                       FastAPI app assembly + error handlers
  config.py                     Settings from environment
  database.py                   Engine/session
  models.py                     SQLAlchemy models
  schemas.py                    Pydantic request/response contracts
  security.py                   JWT auth + organization-scoping enforcement
  audit.py                      Append-only audit event writer
  qualification_registry.py     Versioned registry + AI-eligibility invariant enforcement
  interfaces/
    conclusion_generator.py     V3 contract only (superseded by services/conclusion_generator.py)
    score_engine.py             SUPERSEDED in V4 -- see app/services/score_engine.py
  services/
    conclusion_generator.py     Deterministic verdict/explanation generator (V4.1)
    pipeline_service.py         Full analysis pipeline: parse → analyze → score (V4.1)
    validity_engine.py          H2 semantic gate + strength predicates (bounded starter rule set)
    trust_boundary_service.py   AICandidate -> validation -> Finding pipeline
    floor_engine.py             Critical-risk floor definitions + evaluation
    score_engine.py             Real deterministic scoring (points/caps/severity)
    score_engine_service.py     Compute-and-persist orchestration (no caller-supplied score)
    ai_execution_service.py     Immutable AIExecutionProvenance (1:1 per AnalysisRun)
    ai_reasoner_service.py      AI reasoning with offline fallback (V4.1)
    investigation_service.py    CRUD + full detail builder + role enforcement (V4.1)
    evidence_service.py         Artifact ingestion + real zip export bundles (V4.1)
    (+ analysis_run/fact/finding services from earlier deliveries)
  api/v1/                       Route handlers, including routes_ai.py (trust boundary entry point)
alembic/                        Migrations (0001_initial, 0002_v4_trust_boundary_and_score_engine)
tests/                          Pytest suite (SQLite-backed), 253+ tests confirmed passing
scripts/create_user.py          Bootstrap an org/user
```

See `V4_CHANGELOG.md` and `V4_1_CHANGELOG.md` for the full
IMPLEMENTED / STUBBED / NOT IMPLEMENTED / DEFERRED breakdown, known
limitations, and scope notes.
