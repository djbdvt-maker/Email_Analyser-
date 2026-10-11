# HopZero Architectural Decisions & Invariant Ledger

This document logs all architectural decisions, invariant confirmations, and rationale for HopZero refactoring and integration work. Any proposed change to a locked invariant must be recorded here with justification prior to execution.

---

## 1. Locked Invariants (Frozen)

The following decisions are strictly locked across all work packages:

1. **Facts → Findings → Conclusion → Verdict separation**: An investigator can always trace any verdict back through conclusion and findings to original deterministic facts and evidence.
2. **"Never ask the LLM to establish a fact that deterministic computation can establish more reliably."**
3. **Qualification registry, floors, scoring buckets, and strength values are locked (v1)**: Score is a pure function of validated Findings plus `scoring_model_version`. Analyzers discover, validators establish eligibility, normalizer merges, score engine judges.
4. **LLM has zero scoring authority**: Raw LLM output is persisted strictly as an immutable `llm_candidate_observation` Fact. It must pass the complete validation funnel (schema, qualification, grounding, corroboration). The LLM stage is non-blocking: failure or refusal emits `signal_unavailable` Fact, and the run completes with a deterministic score.
5. **Bounded injection-resistance**: Hostile email content cannot issue instructions, alter facts, lower scores, invent qualification semantics, or trigger floors (false negative remains possible; injection-proof is never claimed).
6. **Preserve history, derive current state, never silently replace a previous interpretation**: AnalysisRun history, Score history, and `InvestigationAction` history are append-only.
7. **Never an automatic irreversible action**: No automated delete, block, open, execute, or forward.
8. **Roles and visibility**: USER sees only own investigations; ANALYST/ADMIN org-wide. USER may only perform `escalation_requested` and `note_added` on own, non-closed investigations; ANALYST/ADMIN can perform all actions.
9. **Offline-first acceptance test**: Fully unplugged `.eml` analysis, verdict, and evidence export succeeds without network; network enrichment adds freshness only.
10. **Evidence claims stay softened**: "Hash-verified, auditable evidence package structured to support the applicable Section 63 BSA certification process"; HopZero does not certify legal admissibility.
11. **Regression corpus safety net**: Outputs of the regression corpus (17 hand-built cases, regression 13b, 6 frozen synthetic Hop-0 cases, and canonical E2E cases) must remain identical after refactors.

---

## 2. Decision Log

### DEC-000: Golden Baseline Snapshot & Safety Net Setup (HZ0)
- **Date**: 2026-10-11
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: Every refactoring package (single-LLM adapter, tool API, core extraction, parser isolation) touches code paths that feed the score and verdict. A byte-exact baseline is necessary to prove zero unintended behavioral drift.
- **Decision**:
  1. Implemented `scripts/golden_runner.py` and `scripts/check_golden` (with `.ps1`, `.bat`, and bash wrappers) to capture and verify:
     - 21 scoring corpus cases (covering the 17 hand-built scenarios, multiplier variations, CF-01..CF-06 floors, CF-01 near miss, and CF-06 negative/13b).
     - 14 `.eml` fixtures (5 canonical E2E fixtures, 6 synthetic Hop-0 cases, and 3 routing edge cases).
  2. Captured full JSON outputs comprising: deterministic Facts, Findings, Score, Verdict, and Conclusion.
  3. Normalized only volatile fields explicitly allowed to vary across independent invocations:
     - Dynamic runtime timestamps in `external_intelligence_provider` when running offline (normalized to `<TIMESTAMP>`).
     - Transient parse-instance UUIDs generated in memory for `CanonicalEmail.id` (normalized to `<UUID>`).
     - Transient database primary-key UUIDs.
  4. Verified that `scripts/check_golden` passes with exit code 0 on clean checkout and exits with code 1 when any fixture is altered.

### DEC-001: Real-Capture Routing Validation & Single-LLM Selection (HZ1)
- **Date**: 2026-10-11
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: 
  1. Hop-0 routing trust walk was tested on synthetic headers, leaving open validation risk against real provider quirks (Gmail webmail spooling, Microsoft 365 Outlook client submissions, unrecognized intermediate relays, and manual forwards).
  2. Local LLM shared between forensic semantic analysis and tool-calling bot must stay resident within 4 GB VRAM and advertise native tool-calling capabilities in Ollama.
- **Decision**:
  1. **Real EML Captures**: Captured 4 anonymized real samples preserving exact header structures, casing, and trace parameters:
     - `real_capture_gmail.eml`
     - `real_capture_m365.eml`
     - `real_capture_unrecognized_relay.eml`
     - `real_capture_manual_forward.eml`
  2. **Hop-0 Trust Walk Fallback**: In webmail submissions (e.g. Gmail internal spooling `Received: by mail-*.google.com ...`), internal intra-cluster hops lack a `from` clause. The routing trust walk was calibrated to select the deepest trusted receiving hop that recorded an `observed_ip`, without expanding trusted relay dataset suffixes in `trusted_receivers_v1.py`.
  3. **Single Local LLM (`hermes3:3b`)**:
     - Evaluated `hermes3:3b` vs `phi3:latest`.
     - `phi3:latest` lacks `tools` capability in Ollama.
     - `hermes3:3b` advertises both `completion` and `tools`, occupies 2,226.9 MB VRAM (< 4 GB constraint), achieved 0% refusal on security lure tests, 100% structured schema compliance, and exhibited zero model reload swap latency (< 46 ms) over 20 alternating calls.

### DEC-002: Shared Single-LLM Client Architecture (HZ2)
- **Date**: 2026-10-11
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: 
  1. Both the Forensic Semantic Analyzer (`ai_reasoner_service.py`) and the BotChain Tool Orchestrator require LLM access.
  2. Running two different models simultaneously exceeds local GPU VRAM budgets (4 GB target); swapping models on each turn introduces 3–8s disk/RAM swap latency.
- **Decision**:
  1. **Unified Protocol (`hopzero/llm/client.py`)**: Defined runtime-checkable `LLMClient` protocol exposing `complete(prompt, json_schema=...)` and `chat(messages, tools=...)`.
  2. **Central Configuration (`config/llm.yaml`)**: Locked default to `hermes3:3b`, `num_ctx: 4096`, `temperature: 0.0`, `seed: 42`, `keep_alive: "5m"`.
  3. **Ollama Adapter (`hopzero/llm/ollama_adapter.py`)**: Implemented non-blocking adapter handling Ollama `/api/generate` and `/api/chat` with `keep_alive: "5m"`. Supports Ollama native `format: <json_schema>` enforcement, tool call parsing (both native and model output fallbacks), refusal detection heuristics (`REFUSAL_TRIGGERS`), and maps failure states to standard HopZero error constants (`AI_UNAVAILABLE_TIMEOUT`, `AI_UNAVAILABLE_CONNECTION_REFUSED`, `AI_REFUSAL`, etc.).
  4. **Semantic Reasoner Integration**: Wired `ai_reasoner_service.py` to route through `OllamaLLMClient` with `PROPOSAL_SCHEMA`. Maintained offline deterministic fallback and non-blocking failure tolerance with zero score disruption.
  5. **Verification**: 10 unit and integration tests added in `03_BACKEND/tests/test_llm_client.py`. Live 20-call residency test verified that model remained continuously resident in VRAM with zero unloads across alternating structured completions and tool-calling chats.
### DEC-003: Tool-Facing API, BotChain Manifest & Operation Design (HZ3)
- **Date**: 2026-10-11
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: Exposing HopZero forensics to BotChain Studio and other automated orchestration agents requires an explicit, secure tool API contract conforming to the BotChain Tool Suite Standard without leaking internal routing complexities or compromising security invariants.
- **Decision**:
  1. **Clean, Predictable Operation IDs**: Configured explicit IDs prefixed with `hopzero_`: `hopzero_get_manifest`, `hopzero_get_version`, `hopzero_analyze_email`, `hopzero_get_headers`, `hopzero_get_indicators`, `hopzero_explain_score`, `hopzero_get_summary`.
  2. **Coarse vs. Fine Operations**:
     - Coarse operation `POST /api/v1/tool/analyze-email` takes raw EML / RFC822 or parsed payload, runs synchronous forensic pipeline, returns standardized report with investigation ID.
     - Fine-grained inspection operations allow agents to query specific sub-components on an existing investigation (`/headers`, `/indicators`, `/explain-score`, `/summary`) without re-running expensive pipeline stages.
  3. **Security & Untrusted Markers**:
     - All user-controlled email content strings (headers, subjects, bodies, attachment names) are marked as untrusted in OpenAPI documentation and API payloads.
     - The default on `POST /api/v1/tool/analyze-email` is `include_body=false` to prevent raw email content from entering downstream LLM context windows unless explicitly requested.
  4. **Zero LLM Scoring Authority in Explanations**: `hopzero_explain_score` is 100% deterministic template-driven, walking category caps, multipliers, and critical floor triggers (CF-01..CF-06) with zero LLM generation.
  5. **BotChain Manifest & Version Contract**: Exposes `GET /tool-manifest` conforming to the BotChain Tool Suite specification and `GET /version` matching the release manifest in `01_REGISTRY/releases/registry-v1.json`.

### DEC-004: Bot-Initiated Actions as Drafts with Human Confirmation (HZ4)
- **Date**: 2026-10-11
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: Invariant 7 strictly states: "Never an automatic irreversible action: No automated delete, block, open, execute, or forward." When external agents (such as BotChain bots) propose remediation or case disposition actions, they must not execute immediately. A human-in-the-loop review workflow is required.
- **Decision**:
  1. **ActionDraft Data Entity**: Implemented `ActionDraft` in `03_BACKEND/app/models.py` with states `PENDING_CONFIRMATION`, `CONFIRMED`, `REJECTED`, `CANCELLED`. Created Alembic migration `0005_action_drafts.py`.
  2. **Automated Actions Propose Drafts Only**: Bots propose actions via `POST /api/v1/investigations/{id}/actions/draft` or the tool-facing `POST /api/v1/tool/investigations/{id}/propose-action`. The action draft is created with `status=PENDING_CONFIRMATION` and `created_by_bot=True`, with zero irreversible changes occurring automatically.
  3. **Evidence Grounding Verification**: For proposed threat response actions (`BLOCK_SENDER`, `BLOCK_DOMAIN`, `BLOCK_IP`, `QUARANTINE`), targets must be strictly grounded in the investigation's current deterministic facts and findings. Arbitrary ungrounded target injection is rejected with HTTP 400.
  4. **RBAC & Explicit Human Confirmation**: Irreversible actions require explicit human confirmation via `POST /api/v1/investigations/{id}/actions/drafts/{draft_id}/confirm`. Invariant 8 RBAC is enforced: sensitive actions require `ANALYST` or `ADMIN` role; regular `USER` / `VIEWER` roles are rejected with HTTP 403. Rejection is supported via `POST .../reject` with mandatory reason.
  5. **Audit Trail Attribution**: Draft creation logs `AuditAction.ACTION_DRAFT_CREATED` with `actor_via="botchain"` (or custom agent name). Confirmation logs `AuditAction.ACTION_DRAFT_CONFIRMED` with `actor_via` and `confirmed_by=user.id`, ensuring full accountability across automated proposal and human authorization.

### DEC-005: Extraction of Shared hopzero-core Package (HZ5)
- **Date**: 2026-10-11
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: HopZero's evolution from a single email-checking monolith into a family of interconnected tools (e.g., Domain & Lookalike Checker, Infrastructure Analyzer) orchestrated via BotChain Studio requires shared domain primitives, common serialization, and cryptographic hashing utilities without duplicating data structures across repositories.
- **Decision**:
  1. **Package Extraction (`hopzero/core`)**: Created a standalone `hopzero.core` module containing:
     - `hashing.py`: Canonical SHA-256 computation (`compute_sha256`, `compute_file_sha256`, `canonical_json_hash`).
     - `models.py`: Shared base models and contracts (`SignalState`, `RawHeader`, `EmailAddress`, `ReceivedHopRaw`, `ExtractedLink`, `ExtractedAttachment`, `EmailBody`, `CanonicalEmail`, `Fact`, `FindingCandidate`, `AnalyzerOutput`, `NormalizationEvent`, `NormalizedField`, `NormalizedEvidence`).
     - `registry.py`: Unified qualification registry loader (`load_registry`, `get_qualification`, `get_floors`, `get_scoring_buckets`) with SHA-256 snapshot verification.
  2. **Cross-Tool Primitives**:
     - `NormalizedEntity`: Typed indicator representation (`entity_type`, `normalized_value`, `raw_value`, `provenance`) for cross-tool indicator passing.
     - `AnalysisRunConfig`: Typed execution configuration supporting offline mode, timeouts, payload limits, and reproducibility anchors (paving the way for HZ8).
  3. **Zero Behavior Change & Full Backwards Compatibility**:
     - Re-exported all base models through `hopzero_forensics.interfaces`, guaranteeing that existing forensic analyzers, normalizers, backend pipelines, and test suites continue to resolve identical types with zero code modifications.
     - Verified zero score drift against the regression baseline: `scripts/check_golden.py` passed 100% byte-for-byte across all 21 scoring cases and 14 EML fixtures.

### DEC-006: Tool Suite Standard & Extracted Domain Checker Tool (HZ6)
- **Date**: 2026-10-11
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: To connect HopZero with BotChain Studio and expand into a modular family of tools, we need a formal standard governing manifest schemas, version reporting, and health contracts, plus an extracted first standalone tool proving multi-tool chaining.
- **Decision**:
  1. **Tool Suite Standard (`docs/TOOL_SUITE_STANDARD.md`)**: Codified discovery (`/tool-manifest`), version (`/version`), health (`/health`), operation ID naming conventions (`{tool}_{op}`), untrusted input markings, and invariant enforcement (zero LLM scoring authority, actions as drafts).
  2. **Standalone Domain & Lookalike Checker Tool (`hopzero/tools/domain/`)**:
     - Extracted domain evaluation into an independent service with zero external network dependencies.
     - Implemented detection for punycode (`xn--`), mixed Unicode scripts, Cyrillic/Greek homoglyphs (`HOMOGLYPH_MAP`), and brand typosquatting against `PROTECTED_BRANDS`.
     - Published dedicated BotChain tool manifest (`/api/v1/domain/manifest`) and version endpoint.
     - Added single (`POST /api/v1/domain/check`) and batch (`POST /api/v1/domain/check-batch`) inspection endpoints.
  3. **BotChain Multi-Tool Chaining**: Verified end-to-end chaining in `test_tool_chaining.py` where Tool 1 (HopZero Email Forensics) extracts indicators from an email, and Tool 2 (Domain Checker) independently evaluates them, producing corroborated findings.

### DEC-007: Parser and Attachment Isolation (HZ7)
- **Date**: 2026-10-11
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: Raw RFC 5322 MIME streams and attachment payloads are untrusted, externally-supplied attack surfaces. Catastrophic backtracking, recursive multipart bombs, oversized attachment inflation, decompression bombs, and parsing crashes must never be able to exhaust server resources or crash the backend pipeline.
- **Decision**:
  1. **Subprocess Isolation Wall (`hopzero.core.isolation`)**:
     - Built `parse_eml_isolated()` running untrusted EML parsing in an isolated worker process (`sys.executable -m hopzero.core.isolation --worker`).
     - Hard OS-level execution timeout (default 15.0s, configurable via `Settings.parser_timeout_seconds`) with immediate process termination upon timeout.
     - Graceful fault tolerance: Subprocess crashes and timeouts produce a structured fallback `CanonicalEmail` marked with `is_truncated=True` and descriptive `parse_warnings` (`PARSER_TIMEOUT`, `PARSER_CRASH`), allowing downstream analyzers and score engine to proceed deterministically.
  2. **MIME and Attachment Resource Caps**:
     - Capped multipart recursion depth at 20 levels via `_walk_bounded` to neutralize MIME recursion bombs without stack overflow.
     - Traversal capped at a maximum of 250 MIME parts.
     - Attachment payload sizes capped at 10 MB per individual part and 25 MB cumulative across all attachments.
     - Attachment count capped at a maximum of 50 extracted attachments.
     - ZIP archive inspection bounded to 10 MB uncompressed ceiling and archive depth <= 2.
  3. **Backend Integration & Golden Verification**:
     - Routed `03_BACKEND/app/services/pipeline_service.py` through `parse_eml_isolated()` with configurable `parser_isolation_mode` ("subprocess", "process_pool", "in_process").
     - Validated 100% byte-for-byte fidelity against the golden baseline: `python scripts/check_golden.py` passed with 0 score drift across 21 scoring cases and 14 EML fixtures.
     - Added 8 dedicated security and recovery tests in `03_BACKEND/tests/test_parser_isolation.py`. Full test suite now passes at 429 tests (0 failures).

### DEC-008: Reproducibility Fields in AnalysisRunConfig (HZ8)
- **Date**: 2026-10-11
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: Forensic auditability requires that every forensic run record the exact LLM execution environment and parameter envelope (`llm.model`, `llm.digest`, `llm.quantization`, `llm.num_ctx`, `llm.options_hash`, `llm.prompt_version`, `llm.schema_version`), enabling exact deterministic replay and verification.
- **Decision**:
  1. **Canonical Config Model & Hashing (`AnalysisRunConfig`)**:
     - Enhanced `hopzero.core.models.AnalysisRunConfig` with explicit `llm` envelope fields and deterministic methods:
       - `compute_options_hash()`: SHA-256 over canonical JSON of `(model, digest, quantization, num_ctx, prompt_version, schema_version, extra_options)`.
       - `compute_reproducibility_fingerprint()`: Canonical SHA-256 fingerprint representing the full deterministic run envelope (`registry_version`, `validity_rule_version`, `offline_mode`, `options_hash`).
       - `to_dict()` and `from_dict()` for lossless database persistence and API serialization.
  2. **Database Persistence & Migration**:
     - Added `config = Column(JSON, nullable=True, default=dict)` to `AnalysisRun` model in `03_BACKEND/app/models.py`.
     - Created Alembic migration `0006_analysis_run_config.py`.
     - Updated `create_analysis_run()` in `analysis_run_service.py` to accept and persist `AnalysisRunConfig`.
  3. **Live Metadata Resolver & Provenance**:
     - Implemented `resolve_llm_reproducibility()` in `ai_reasoner_service.py`: dynamically queries live Ollama instance (`/api/tags`) for exact model digest (`a8851c...`) and quantization level (`Q4_K_M`) when online, with deterministic fallbacks when offline.
     - Updated `pipeline_service.py` to ensure `run.config` always records the complete reproducibility envelope upon execution.
  4. **Tool API Inspection Endpoint**:
     - Added `GET /api/v1/tool/investigations/{investigation_id}/reproducibility` (`hopzero_inspect_reproducibility`) exposing the full envelope to BotChain Studio.
     - Verified with 4 unit/integration tests in `03_BACKEND/tests/test_analysis_run_reproducibility.py`. Full test suite now passes at 433 tests (0 failures).

### DEC-009: Injection Resistance, Offline Acceptance, and Release Governance (HZ9)
- **Date**: 2026-10-11
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: Finalizing the HZ0–HZ9 roadmap requires rigorous adversarial injection resistance tests (guaranteeing that malicious content inside email bodies cannot influence deterministic scoring or execute actions), a two-phase offline acceptance test script, and an operational release plan.
- **Decision**:
  1. **Prompt Injection & Adversarial Resistance Suite**:
     - Implemented `03_BACKEND/tests/test_injection_resistance.py` covering direct instruction override ("IGNORE ALL PREVIOUS INSTRUCTIONS"), system directive spoofing, role confusion, exfiltration attempts, and benign injection discussion robustness.
     - Confirmed that untrusted content boundaries strictly demarcate email text, deterministic pre-scans detect attack patterns without score distortion, schema validation immediately drops freeform/exfiltration text, and the 4-gate trust boundary rejects fabricated candidate claims.
     - Enforced Invariant 1 (zero scoring authority): LLMs cannot modify scores or trigger floors directly.
  2. **Two-Phase Offline Acceptance Test**:
     - Created `scripts/offline_acceptance_test.py` (with `.bat` and `.ps1` cross-platform runners).
     - Phase 1 verifies qualification registry cryptographic SHA-256 integrity, compiler compilation, and golden regression baseline byte-for-byte.
     - Phase 2 runs in strictly offline mode (`HOPZERO_LLM_PROVIDER=offline_deterministic_fallback`), verifying parser isolation, injection resistance, drafts-only action governance, reproducibility envelopes, and BotChain tool APIs and multi-tool chaining.
  3. **Release Plan & Operational Runbook**:
     - Published `docs/RELEASE_PLAN.md` documenting production deployment checklists, BotChain Studio integration contracts, offline operation runbooks, and disaster recovery.
  4. **Verification**:
     - Two-phase acceptance test executed and passed 100% cleanly in 43.77s.
     - Golden baseline matches 100% byte-for-byte (21 scoring cases + 14 EML fixtures, 0 score drift).
     - Full test suite passes at 434 tests, 1 skipped, 0 failures.
### DEC-010: Commercial Readiness - Universal Environment & Startup Invariants
- **Date**: 2026-10-11
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: Transitioning from developer prototype to commercial-grade software requires deterministic cross-platform execution on any machine (Windows, Linux, macOS), strict dependency locking, graceful startup validation, and zero line-ending drift on forensic fixtures.
- **Decision**:
  1. **Runtime & Dependency Pinning**:
     - Created `.python-version` pinning Python `3.12.10`.
     - Created root `pyproject.toml` pinning Python range `>=3.12,<3.13`.
     - Generated pinned `requirements.lock` (root and `03_BACKEND/requirements.lock`).
     - Verified frontend lockfile reproducibility via clean `npm ci`.
     - Specified supported database engine ranges (SQLite stdlib for Desktop/Lite, PostgreSQL 15.x–17.x for Server).
  2. **Startup Settings Validation**:
     - Added `ConfigurationError` and `validate_settings()` in `03_BACKEND/app/config.py`.
     - Called in FastAPI `lifespan` before database connection pools or socket listeners initialize.
     - Provides clear diagnostic messages and actionable remediation hints for invalid DB schemes, insecure JWT keys in production, invalid isolation modes, and invalid LLM providers.
  3. **Filesystem & App-Data Path Resolution**:
     - Implemented `hopzero.core.paths` using `pathlib.Path` to resolve OS-native application directories (`%LOCALAPPDATA%\\HopZero` on Windows, `~/.local/share/hopzero` on Linux, `~/Library/Application Support/HopZero` on macOS), with support for portable/container overrides (`HOPZERO_DATA_DIR`, `HOPZERO_PORTABLE`).
  4. **Time & Encoding Invariants**:
     - Enforced `encoding="utf-8"` or binary on all file reads and writes across the repository.
     - Implemented `hopzero.core.clock` providing timezone-aware UTC datetimes and `frozen_clock()` context manager for deterministic time-sensitive forensics and testing.
  5. **Git Attributes & Forensic Integrity**:
     - Added `.gitattributes` marking `*.eml` and `*.msg` as binary files to prevent CRLF line-ending transformation, guaranteeing cryptographic SHA-256 byte stability across operating systems.
### DEC-011: Commercial Readiness - Native One-Click Execution & Zero-Docker Architecture
- **Date**: 2026-10-11
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: Commercial desktop deployment requires instant one-click execution without mandatory Docker dependencies, automatic database migration with backup protection, conflict-free port selection, health supervision, and diagnostic self-healing.
- **Decision**:
  1. **One-Click Native Launcher**:
     - Implemented `scripts/launch.py` and native wrapper scripts (`hopzero.bat`, `hopzero.ps1`, `hopzero.sh`).
     - Performs automatic port discovery for backend (8000+) and frontend (5173+) using socket binding checks.
     - Warms up resident model (`hermes3:3b`) in Ollama before browser launch.
     - Supervise backend health polling with generous timeout before automatically opening the SOC dashboard.
     - Handles graceful signal trapping (SIGINT / SIGTERM) to terminate spawned child services cleanly without zombie processes.
  2. **Comprehensive Diagnostic Command (`doctor`)**:
     - Implemented `scripts/doctor.py` checking Python version (3.12.x), Node/npm availability, free disk space (>=5 GB recommended), storage read/write permissions, database connectivity, Ollama daemon and resident model existence, forensic registry SHA-256 release hash, and golden output presence.
     - Formats failures with actionable `--> FIX HINT:` guidance.
  3. **Embedded Database & Pre-Upgrade Backups**:
     - Standardized SQLite for Desktop/Lite editions with `PRAGMA journal_mode=WAL` and `PRAGMA busy_timeout=5000` for concurrent multi-threaded performance.
     - Added `backup_database_before_upgrade()` to automatically snapshot the active database into `backups/` before schema migrations run on startup.
  4. **Optional Start at Login**:
     - Created `scripts/autostart.py` supporting Windows Task Scheduler (`schtasks`), Linux (`~/.config/autostart/hopzero.desktop`), and macOS (`LaunchAgents`).
### DEC-012: Commercial Readiness - Hardware Auto-Profiling & Edition Strategy
- **Date**: 2026-10-11
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: A commercial software release must scale gracefully from minimal laptops to GPU workstations and multi-tenant servers without manual tuning, while guaranteeing that both HopZero forensics and BotChain tools share the identical local LLM execution context.
- **Decision**:
  1. **Cross-Platform Native Hardware Auto-Detection**:
     - Implemented `hopzero.core.hardware` detecting physical/logical CPU count, system RAM (via native `GlobalMemoryStatusEx` on Windows, `/proc/meminfo` on Linux, and `sysctl` on macOS without requiring external dependencies like `psutil`), and GPU/VRAM (via `nvidia-smi` query).
  2. **Edition Recommendation Engine**:
     - Classifies host capabilities into 4 commercial edition tiers:
       - **Lite**: RAM < 8 GB or <= 4 CPU cores (WAL SQLite, aggressive Laya pre-screening, offline/quantized inference).
       - **Standard**: RAM >= 8 GB, >= 4 CPU cores, entry/integrated GPU (WAL SQLite, resident Ollama `hermes3:3b`, balanced pre-screening).
       - **Pro**: RAM >= 16 GB, dedicated GPU with VRAM >= 4 GB (WAL SQLite/Postgres, full GPU acceleration, high-throughput batching).
       - **Server**: Multi-user, multi-tenant host with RAM >= 32 GB (PostgreSQL database, enterprise worker pools).
     - Persists profile to `%LOCALAPPDATA%\\HopZero\\hardware_profile.json` on first run.
  3. **One Shared Local Model Invariant**:
     - Strictly enforced across HopZero core forensic reasoning and BotChain bot tools:
       - Model: `hermes3:3b`
       - Digest: `a8851c5041d400c8eece484771e0a9f438e6500de9f22150ef2863bf7209fbd9`
       - Quantization: `Q4_K_M`
       - Context Window: `4096` tokens
       - Base URL: `http://localhost:11434`
     - Precludes conflicting model deployments from exhausting the 4 GB VRAM envelope.
  4. **System API Endpoints**:
     - Added `GET /api/v1/system/edition` and `GET /api/v1/system/doctor` in `routes_system.py`.
### DEC-013: Commercial Readiness - Installer Architecture, Rollback & Signed Packaging
- **Date**: 2026-10-11
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: Delivering a trusted commercial release requires an interactive and automated installer that verifies prerequisites, shows an explicit installation plan, asks user consent, rolls back on any failure, isolates third-party tools (winget for Ollama without touching GPU drivers), and cryptographically signs distribution bundles.
- **Decision**:
  1. **Consent-Driven Installation & Prerequisites**:
     - Implemented `scripts/install.py` with structured prerequisite validation (Python 3.12, storage capacity, architecture).
     - Formats a clear installation plan detailing components, edition recommendations, and paths.
     - Asks explicit user consent (`[Y/n]`) before making filesystem or environment changes (supports `-y` / `--yes` for automated deployments).
  2. **Safe Third-Party Service Management**:
     - Integrates official Ollama installation via Windows Package Manager (`winget install Ollama.Ollama`).
     - Strictly enforces the GPU safety rule: installer NEVER touches, installs, or modifies GPU display drivers or CUDA system layers.
  3. **Atomic Transactional Rollback**:
     - Created `InstallTransaction` in `scripts/install.py` tracking created paths and configuration changes.
     - Intercepts exceptions or aborted installations to cleanly remove created files in reverse order and restore previous state.
  4. **Cryptographic Release Signing & Verification**:
     - Implemented `hopzero.core.signatures` providing streaming SHA-256 manifest hashing, HMAC-SHA256 signature generation (`sign_manifest`), and constant-time verification (`verify_manifest_signature`, `verify_directory_against_manifest`).
     - Implemented `scripts/package_release.py` building the production frontend bundle, bundling standalone distribution artifacts, and generating signed release archives (`hopzero-4.2.0-standalone.zip` and `.sha256`).
     - Added `scripts/verify_update.py` for verifying auto-update archives prior to extraction.
  5. **Air-Gapped Offline Support**:
     - Added `--offline` flag in `scripts/install.py` allowing complete installation from local pre-cached wheels, assets, and weights without external internet access.
### DEC-014: Commercial Readiness - Multi-OS CI, Smoke Testing & Release Automation
- **Date**: 2026-10-12
- **Status**: ACCEPTED & IMPLEMENTED
- **Context**: Release engineering requires enterprise-grade CI pipelines across all target operating systems, automated clean-install smoke tests verifying `/health` and OpenAPI routes, strict air-gapped network jail tests, nightly upstream drift monitoring, and automated release publishing.
- **Decision**:
  1. **Multi-OS Matrix CI Pipeline**:
     - Upgraded `.github/workflows/ci.yml` matrix covering Windows (`windows-latest`), Linux (`ubuntu-latest`), and macOS (`macos-latest`) with Python 3.12 and Node.js 20.
     - Runs bytecode compilation, frontend production build (`npm run build`), golden regression check (`scripts/check_golden.py`), full pytest suite, and two-phase offline acceptance test.
  2. **Automated Clean-Install Smoke Test**:
     - Implemented `scripts/smoke_test.py` simulating fresh customer installation (`scripts/install.py -y --offline`), spawning backend service on dynamic port, verifying `/health`, `/api/v1/system/edition`, and `/api/v1/tool/manifest`, and shutting down cleanly.
  3. **Strict Air-Gapped Network Jail**:
     - Implemented `scripts/test_network_isolation.py` monkeypatching the OS socket layer to block any outbound connection to non-localhost destinations.
     - Verified that full email parsing, qualification compilation, deterministic risk scoring, and domain lookalike checks execute with 0 network leaks.
  4. **Nightly Upstream Drift Monitoring**:
     - Created `.github/workflows/nightly-drift.yml` scheduled at 02:00 UTC daily.
     - Builds against unpinned upstream packages and verifies zero drift against golden outputs; opens an automated GitHub issue alert if regressions or drift are detected.
  5. **Dependabot & Release Automation**:
     - Created `.github/dependabot.yml` tracking `pip`, `npm`, and GitHub Actions.
     - Created `.github/workflows/release.yml` triggering on `v*` tags to build and publish signed release archives (`hopzero-4.2.0-standalone.zip` and `.sha256`).
     - Updated `CHANGELOG.md` with semantic version `[4.2.0]`.
  6. **Verification**:
     - Added 4 unit tests in `03_BACKEND/tests/test_ci_and_release_automation.py`. Full test suite passes at 462 passed, 1 skipped, 0 failures. Golden regression baseline matches 100% byte-for-byte.
