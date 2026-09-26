# HopZero — Master Hardening Pass Changelog

This changelog records the changes made in the consolidated hardening and integration pass on the existing HopZero project (`C:\Users\HELLO\Desktop\sih`).

## Summary of Changes

### 1. Canonical InvestigationStatus Lifecycle (`03_BACKEND`, `04_FRONTEND`)
- **Strict Canonical Statuses**: Canonical `InvestigationStatus` values are strictly:
  `AWAITING_ANALYSIS`, `UNDER_REVIEW`, `CONFIRMED`, `FALSE_POSITIVE`, `ESCALATED`, `CLOSED`.
- **Elimination of `ANALYZED`**: Completely removed the redundant `ANALYZED` state from `InvestigationStatus` enum (`models.py`), frontend types (`contract.ts`), and mock fixtures (`mockFixtures.ts`).
- **Direct Transition to `UNDER_REVIEW`**: Completed automated analysis transitions `AWAITING_ANALYSIS` directly to `UNDER_REVIEW`.
- **Preservation of Human Disposition**: A new `AnalysisRun` does NOT overwrite an existing human disposition (`CONFIRMED`, `FALSE_POSITIVE`, `ESCALATED`, `CLOSED`). Automated analysis only transitions status if the investigation is in `AWAITING_ANALYSIS`.
- **Reopen Semantics**: Action `reopen` transitions resolved investigations back to `UNDER_REVIEW` and explicitly does NOT create a new `AnalysisRun`.

### 2. Server-Side Role Enforcement & Analyst Actions
- **State-Changing Actions Restricted**: `confirm_malicious`, `false_positive`, `needs_escalation`, `reopen`, and `close` are strictly restricted to `ANALYST` and `ADMIN` roles. Unauthorized users receive HTTP 403 Forbidden.
- **`add_note` Scoping**: Permitted for all authenticated users belonging to the organization; emits dedicated `NOTE_ADDED` audit event and does NOT mutate investigation status.
- **Tenant Isolation**: Organization scoping strictly enforced (cross-organization access returns HTTP 404 Not Found).
- **Legacy Aliases Rejected**: `CONFIRM`, `CONFIRM_MALICIOUS`, `MARK_FALSE_POSITIVE`, `ESCALATE`, `NOTE` rejected with HTTP 422.
- **False Positive Rationale**: `false_positive` strictly requires `false_positive_reason` or `note`, rejecting with HTTP 422 if omitted.

### 3. Audit Event Model & Frontend Type Classification
- **Preserved Model**: Retained `INVESTIGATION_STATUS_CHANGED`, `NOTE_ADDED`, `INVESTIGATION_REOPENED` with structured metadata.
- **Type Classification**: Backend helper `classify_audit_action_type` and frontend service map audit events to declared types:
  - `to = CONFIRMED` → `confirmation`
  - `to = ESCALATED` → `escalation`
  - `to = CLOSED` → `close`
  - `NOTE_ADDED` → `note`
  - `INVESTIGATION_REOPENED` → `reopen`
  - `EVIDENCE_EXPORTED` → `export`
  - Ingestion events → `ingestion`
  - Analysis events → `analysis`

### 4. Score Engine / Conclusion Generator Separation
- **Strict Decoupling in `score_engine_service.py`**:
  - `compute_and_persist_score()` strictly computes numeric scoring (points, category caps, floor triggers, severity) via `score_engine.compute_score()` and persists the `ScoreConclusion` row. It does NOT instantiate `ConclusionGenerator` and does not set verdict or explanations.
  - `generate_and_persist_conclusion()` is a separate function invoked by the orchestration layer that executes `ConclusionGenerator.generate()` and updates the `ScoreConclusion` record.
- **Pipeline Orchestration in `pipeline_service.py`**:
  - Pipeline explicitly executes Step 1 (Score Engine -> `compute_and_persist_score`) followed by Step 2 (Orchestration invokes `generate_and_persist_conclusion` with score output, run findings, and AI status) before transitioning run to `COMPLETED`.
- **Score API Route in `routes_findings.py`**:
  - Direct score endpoint explicitly coordinates the two steps sequentially.
- **ConclusionOutput Provenance**: Populates `conclusion`, `explanation`, `supporting_finding_ids` (persisted Finding IDs only), `generator_version` (`conclusion-generator-v1`), and provenance dictionary.

### 5. Canonical Registry Authority (`01_REGISTRY`)
- **Cryptographic Digest**: Verified `01_REGISTRY/releases/registry-v1.sha256` against `01_REGISTRY/releases/registry-v1.json` (`a8f04ed7c2eaa725a3a29c3c2af94efa04e3e086cb38d33b6f2d9112477bc1fb`).
- **Single Source of Truth**: All 41 qualification definitions, AI eligibility, claim signatures, maximum strengths, 6 floor predicates, and 10 scoring category caps derive authoritatively from the canonical registry.
- **AI Eligibility**: Exactly 5 qualifications are marked `ai_eligible: true` (`CREDENTIAL_PHISHING_LINK`, `EXECUTIVE_IMPERSONATION`, `EXPLICIT_BRAND_REPRESENTATION_CLAIM`, `FINANCIAL_REQUEST`, `GENERIC_SUSPICION`). `CREDENTIAL_PHISHING_LINK` is confirmed AI-eligible per the locked specification.

### 6. Forensics / Q40 (`CF-06:INDEPENDENT_TRUSTED_CONTRADICTION`)
- **Strengthened Implementation**: In `02_FORENSICS/hopzero_forensics/analyzers/routing.py`, upgraded Q40 from a simple host-equality heuristic to strictly establish the locked condition: an independent trusted routing record contradicts the relevant claimed or observed path.
- **Evidence Grounding**: Verified that the untrusted hop claims routing path from a trusted host, while the observed transmission source (observed IP or unverified infrastructure) contradicts the verified infrastructure of the trusted provider.
- **Supporting Fact IDs**: Finding candidates preserve both the contradiction fact (`routing-independent-contradiction-{seq}`) and the trusted receiver evidence fact (`routing-trust-{seq}`).
- **Negative Conditions Verified**: No Received headers, unknown relays, unfamiliar IPs, external IPs, generic malformedness, SPF/DKIM/DMARC failures, display-name mismatches, and LLM suspicion do NOT emit Q40 (`UNKNOWN ≠ CONTRADICTORY`).
- **Terminology**: Probable origin IPs are strictly labeled "candidate probable-origin IP", never "attacker IP".

### 7. Forensics / Q41 (`CF-06:STRUCTURAL_IMPLAUSIBILITY`)
- **Preserved Explicit Invariant**: Preserved cross-provider identity break detection within the contiguous trusted receiving boundary (`boundary_index >= 1`).
- **No Speculative Broadening**: Intentionally did not broaden Q41 into generic malformedness, external infrastructure, unfamiliar routing, or provider differences outside the trusted boundary.

### 8. Six Forensic Floors (CF-01 through CF-06)
- **CF-01**: `PROTECTED_BRAND_LOOKALIKE_DOMAIN` AND `EXPLICIT_BRAND_REPRESENTATION_CLAIM` (min Moderate) -> High minimum. Verified domain lookalike is not confused with URL lookalike.
- **CF-02**: `EXECUTIVE_IMPERSONATION` AND `FINANCIAL_REQUEST` (min Moderate) -> High minimum.
- **CF-03**: `CREDENTIAL_PHISHING_LINK` AND `IDENTITY_ANOMALY` (min Moderate) -> High minimum.
- **CF-04**: `SUSPICIOUS_ATTACHMENT` AND `IDENTITY_ANOMALY` (min Moderate) -> High minimum.
- **CF-05**: `CONFIRMED_MALICIOUS_INDICATOR` (Strong) -> High minimum.
- **CF-06**: `ROUTING_FABRICATION_QUALIFIED` OR `CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE` OR `CF-06:INDEPENDENT_TRUSTED_CONTRADICTION` OR `CF-06:STRUCTURAL_IMPLAUSIBILITY` -> High minimum.

### 9. AnalysisRun Lifecycle & Pointer Semantics
- **Allowed Statuses**: Exactly `QUEUED`, `PARSING`, `ANALYZING`, `SCORING`, `COMPLETED`, `FAILED`, `CANCELLED`.
- **Pointer Invariant**: `investigation.current_analysis_run_id` points ONLY to the latest usable `COMPLETED` run. Queued, running, failed, or cancelled runs never replace it. If no completed run exists, remains null.

### 10. Public API Reconciliation
- **Canonical Endpoints**:
  - `POST /api/v1/investigations`
  - `GET /api/v1/investigations`
  - `GET /api/v1/investigations/{id}`
  - `POST /api/v1/investigations/{id}/artifacts`
  - `POST /api/v1/investigations/{id}/analyze`
  - `GET /api/v1/investigations/{id}/findings`
  - `GET /api/v1/investigations/{id}/evidence`
  - `GET /api/v1/investigations/{id}/audit`
  - `POST /api/v1/investigations/{id}/actions`
- **Legacy Routes Deprecated**: In `03_BACKEND/app/api/v1/routes_investigations.py`, added OpenAPI `deprecated=True` tags and docstrings to `GET /{id}/details`, `POST /{id}/status`, and `POST /{id}/reopen` to guide clients toward the canonical action and evidence endpoints.

### 11. Frontend Presentation & Safety
- **No Semantic Fabrication**: In `04_FRONTEND/src/services/api.ts`, eliminated synthetic fallbacks that invented `"run-1"` or assumed `"COMPLETED"` when `current_analysis_run_id` is null.
- **No Client-Side Decision Derivation**: Verified that frontend renders backend-authored scores, severities, and verdicts directly; zero client-side calculation of security verdicts.
- **Untrusted Plaintext Rendering**: Verified zero usage of `dangerouslySetInnerHTML` in application code; email body rendered as plain escaped text; attachments displayed as metadata only without auto-execution.

### 12. Export Hash Integrity
- **Actual Bundle Hashing**: In `03_BACKEND/app/services/evidence_service.py`, `export_bundle_sha256` hashes the exact bytes of the in-memory ZIP bundle (containing artifact and `manifest.json`), mathematically verified distinct from `original_artifact_sha256`.

### 13. n8n Orchestration Discipline
- **Zero Security Reasoning**: Preserved n8n workflow (`06_N8N/workflows/hopzero_gmail_ingestion.json`) as ingestion/orchestration only.
- **Raw RFC 5322 Bytes**: Direct Buffer-level base64url decoding without UTF-8 re-encoding; 25 MB ceiling enforced; provider ID idempotency; no scoring or threat detection in n8n.

### 14. Qualification Compiler Strengthening & Clean Hash Design
- **Domain-Specific Multi-Pass Validator**: `01_REGISTRY/compiler/compile.py` now executes passes A through L (qualification code uniqueness, required fields, strength ordering, producer validation, AI eligibility rules, allowed claim signatures, floor definitions, floor requirement cross-references, scoring bucket caps, category consistency, deterministic serialization, external SHA-256 hash manifest).
- **Clean SHA-256 Hash Manifest**: Eliminated circular self-referential hashing. The release file `registry-v1.json` is signed externally into `registry-v1.sha256`.
- **Compiler Rationale**: Comprehensive 12-point justification and ASCII architecture documented in `docs/COMPILER_RATIONALE.md`.
- **CF-01 Same Protected Brand Requirement**: In `floor_engine.py`, CF-01 enforces target brand intersection between lookalike domain and brand representation claims.

### 15. Locked 9-Bucket Scoring Architecture & Normalization
- **Authoritative 9 Buckets**: Replaced legacy 10-bucket caps with the locked 9 categories: `Identity` (20), `Authentication` (16), `Domain` (16), `URL` (22), `Attachment` (20), `Infrastructure` (14), `Routing` (20), `Social Engineering` (14), `Threat Intelligence` (24).
- **Base Weights & Evidence-Only**: Tier 1 (24, 22, 20), Tier 2 (16, 15, 15, 15, 13, 14, 16), Tier 3 (8, 8, 6, 6, 8, 7, 9, 5, 8, 7, 7, 6, 8, 9, 5). Exactly 16 qualifications designated `evidence_only` with `base_weight: 0`.
- **Strength Multipliers**: `Weak: 0.5x`, `Moderate: 1.0x`, `Strong: 1.5x`, `Negligible: 0.0x`. Completely removed obsolete `STRENGTH_POINTS = {Negligible: 0, Weak: 8, Moderate: 18, Strong: 30}` and the 40-point `all_weak` ceiling.
- **Score Normalization**: Theoretical raw max = 166. Normalized score = `round(raw_score / 166 * 100)` clamped to `0–100`.
- **Severity Boundaries**: `0–29 LOW`, `30–54 MEDIUM`, `55–74 HIGH`, `75–100 CRITICAL`. Floors elevate severity (e.g. CF-01..CF-06 floor is `HIGH`) without modifying numeric score.
- **Canonical Verdicts**: Exactly 4 canonical values (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`, `INDETERMINATE`). Legacy non-canonical strings purged.
### 16. Score Engine Registry Source of Truth
- **Direct Registry Weight Resolution**: `score_engine.py` dynamically resolves base weights via `get_qualification(finding.qualification_code).base_weight`, establishing the compiled registry `01_REGISTRY/releases/registry-v1.json` as the single authoritative source of truth.
- **Spec Cross-Verification**: Added `verify_registry_against_spec()` asserting that all 41 qualifications, 16 evidence-only markers, and locked base weights in code strictly match the compiled registry.

### 17. User-Guided Re-Analysis Engine (`03_BACKEND`, `04_FRONTEND`)
- **First-Class Feedback Model**: Added `UserFeedback` model and `FeedbackType` enum (`SPAM_REPORTED`, `PHISHING_REPORTED`, `ANALYSIS_DISPUTED`).
- **Non-Destructive Re-Analysis**: Feedback triggers a new `AnalysisRun` with `user_feedback_signal` fact, without overwriting, mutating, or erasing prior analysis runs.
- **AI Trust Boundary & Grounding**: User feedback is ingested as contextual signal only; it cannot directly force a `MALICIOUS` verdict or score increase without forensic qualification.
- **Run Comparison**: Added `compare_analysis_runs()` service and `/api/v1/investigations/{id}/runs/compare` endpoint returning score delta, severity transitions, newly surfaced findings, and resolved findings.

### 18. Threat Response & Provider-Neutral Enforcement Framework (`03_BACKEND`, `04_FRONTEND`)
- **EnforcementProvider Interface**: Defined abstract `EnforcementProvider` contract and implemented `MockLocalEnforcementProvider` (clearly labeled `is_demo=True`, tracking local blocks, simulated latency, failure handling).
- **Strict Target Normalization**: Implemented deterministic validators (`normalize_sender`, `normalize_domain`, `normalize_ip` with Python 3.13 link-local/loopback precedence).
- **Evidence Grounding Verification**: Enforces `validate_target_grounded()`; targets must strictly originate from extracted facts of the investigation.
- **Role-Based Authorization & Lifecycle**: Enforces `require_analyst_or_admin()`; actions advance through explicit states: `REQUESTED` -> `AUTHORIZED` -> `EXECUTED` (or `REJECTED` / `FAILED`).
- **Immutable Audit Trail**: Every action transition logs dedicated audit events (`ENFORCEMENT_REQUESTED`, `ENFORCEMENT_AUTHORIZED`, `ENFORCEMENT_EXECUTED`, `ENFORCEMENT_REJECTED`, `ENFORCEMENT_FAILED`).

### 19. Frontend Direct Canonical API Integration (`04_FRONTEND`)
- **Elimination of Deprecated `/details`**: Removed all legacy calls to `/details`. Findings and technical evidence are fetched directly from canonical `/findings` and `/facts` endpoints.
- **Level 1 Consumer Feedback UI**: Integrated user feedback submission modal in `Level1ConsumerVerdict.tsx`.
- **Level 2 Threat Response UI**: Added interactive Threat Response & Provider-Neutral Enforcement panel in `Level2WhyAndAction.tsx` with grounded target selection, action dispatch, authorization modal, and demo disclaimer.

### 20. Complete Test Suite Baseline & Verification
- **01_REGISTRY**: 12 passed (compiler multi-pass validator and hash integrity tests).
- **02_FORENSICS**: 99 passed (all 7 analyzers, parser security, Q40/Q41 routing).
- **03_BACKEND**: 239 passed (includes score engine registry truth, user feedback, enforcement lifecycle, and end-to-end demo workflow).
- **05_QA**: 15 passed (canonical scoring corpus regression cases).
- **06_N8N**: 4 passed (ingestion and integrity tests).
- **Total Test Baseline**: **369 / 369 passed (100% green)**.
- **Frontend Production Build**: `npm run build` succeeds cleanly with 41 modules transformed and 0 TypeScript errors.

---

## Packaging and Delivery Invariants

1. **In-Place Modification**: All modifications have been made directly in place within the provided repository at `C:\Users\HELLO\Desktop\sih`.
2. **Zero ZIP Files Generated**: Per the user's explicit mandate ("do not give me a new zipfile, just make changes directly into the main sih file only"), all code, documentation, migrations, tests, and configuration changes are delivered strictly in place in `C:\Users\HELLO\Desktop\sih` with no zip archive produced.

