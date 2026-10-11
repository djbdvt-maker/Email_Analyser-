# HopZero Implementation Status

**Last Updated**: 2026-10-11  
**Test Suite**: 421 passed, 1 skipped (0 failures)  
**Golden Baseline**: 21 scoring cases + 14 email fixtures passing byte-for-byte

---

## 1. System Version Manifest

| Component | Identifier / Version | Description |
|---|---|---|
| **Backend API** | `2.0.0` | FastAPI core service (`03_BACKEND/app/main.py`) |
| **Forensics Module** | `1.0.0` (`team3-baseline-v1`) | Email Forensics parser, normalizer, analyzers (`02_FORENSICS`) |
| **Registry Version** | `v1` | Compiled qualification and scoring registry |
| **Registry Release SHA-256** | `1047f1db05dd6fe51d20e124d3e42e7d7a20e985993afddfc08759942ee2a44d` | Byte integrity hash of `01_REGISTRY/releases/registry-v1.json` |
| **Compiler Version** | `hopzero-compiler-v1.0.0` | Registry compiler (`01_REGISTRY/compiler/compile.py`) |
| **Validity Engine** | `vr-v1` | Validity rules and criteria evaluator |
| **Score Engine** | `score-engine-v2` | Pure function computing scores and floors |
| **Conclusion Generator** | `conclusion-generator-v2` | Deterministic template-driven conclusion and canonical verdict |
| **Trusted Receivers** | `v1` | Curated receiving infrastructure patterns (`config/trusted_receivers_v1.py`) |
| **Normalization Policy** | `v1` | Mechanical Unicode and text normalization policy (`config/normalization_policy_v1.py`) |
| **Infrastructure Reputation** | `infra_rep_v1` | Static bad ASNs and bulletproof prefixes (`config/infrastructure_reputation_v1.py`) |
| **Protected Brands** | `protected_brands_v1` | Curated brand domains and display names (`config/protected_brands_v1.py`) |
| **Prompt Schema** | `prompt-v1` | Semantic analyzer candidate proposal schema |

---

## 2. Work Packages Roadmap Status

| Work Package | Title | Status | Notes |
|---|---|---|---|
| **HZ0** | **Baseline and safety net** | **Implemented** | Golden snapshot recorded (`05_QA/golden/golden_outputs.json`), `scripts/check_golden` operational, `pytest` verified (394 passed, 1 skipped), `DECISIONS.md` and `HOPZERO_STATUS.md` created. |
| **HZ1** | **Close open validation work** | **Implemented** | 4 real `.eml` captures recorded (`real_capture_gmail.eml`, `real_capture_m365.eml`, `real_capture_unrecognized_relay.eml`, `real_capture_manual_forward.eml`), routing trust walk calibrated for webmail intra-cluster hops, local LLM benchmark completed (`hermes3:3b` selected, 2.2 GB VRAM, 0% refusal, tool-capable). |
| **HZ2** | **Shared single-LLM adapter (`LLMClient`)** | **Implemented** | `hopzero/llm/client.py` protocol, `OllamaLLMClient` adapter (`hopzero/llm/ollama_adapter.py`), `config/llm.yaml`, structured output schema via `PROPOSAL_SCHEMA`, tool calling support, non-blocking fallback, 10 unit/integration tests (`test_llm_client.py`), verified 20 sequential calls residency check with 0 model unloads. |
| **HZ3** | **Tool-facing API and manifest** | **Implemented** | Tool-facing API in `03_BACKEND/app/api/v1/routes_tool.py`, clean operationIds prefixed with `hopzero_*`, BotChain tool manifest (`/tool-manifest`), version endpoint (`/version`), coarse analysis (`POST /api/v1/tool/analyze-email` with `include_body=false` default and untrusted string markers), fine-grained inspection operations (`/headers`, `/indicators`, `/explain-score`, `/summary`), deterministic template-driven score explanations with category caps/floors, 6 unit/contract tests passing (`test_tool_api.py`). |
| **HZ4** | **Bot-initiated actions as drafts** | **Implemented** | `ActionDraft` entity in database (`action_drafts`), Alembic migration `0005_action_drafts.py`, `action_draft_service.py`, endpoints for draft proposal (`POST /actions/draft`), retrieval, human confirmation (`POST /confirm`), and rejection (`POST /reject`), grounding validation for proposed threat response targets, RBAC check requiring ANALYST/ADMIN for irreversible actions, audit trail tracking `actor_via="botchain"` and `confirmed_by`, tool API endpoint `hopzero_tool_propose_action` added to BotChain manifest, 7 tests passing (`test_action_drafts.py`). |
| **HZ5** | **Extract shared `hopzero-core` package** | **Implemented** | Extracted shared domain primitives into `hopzero.core` (`hashing.py`, `models.py`, `registry.py`), implemented `NormalizedEntity` cross-tool indicator representation and `AnalysisRunConfig`, verified canonical SHA-256 and JSON hashing, backed `hopzero_forensics.interfaces` with `hopzero.core.models` for 100% backwards-compatibility, 5 tests passing (`test_hopzero_core.py`), 0% golden drift. |
| **HZ6** | **Tool Suite Standard and extracted domain tool** | **Implemented** | Published `docs/TOOL_SUITE_STANDARD.md`, extracted standalone Domain & Lookalike Checker tool (`hopzero/tools/domain/`), BotChain manifest (`/api/v1/domain/manifest`), version/health endpoints, single/batch check endpoints, homoglyph and brand lookalike detection, BotChain two-tool chaining test verified, 8 tests passing (`test_domain_tool.py`, `test_tool_chaining.py`). |
| **HZ7** | **Parser and attachment isolation** | **Implemented** | Subprocess isolation wall in `hopzero.core.isolation`, hard OS-level execution timeout (default 15.0s) with forceful termination, structured fallback `CanonicalEmail` generation on crash/timeout (`is_truncated=True`, `parse_warnings`), recursion bomb defense via `_walk_bounded` (depth cap 20, max parts 250), attachment payload caps (10 MB per part, 25 MB cumulative, max 50 parts), ZIP inspection ceiling (10 MB uncompressed, depth <= 2), pipeline service integration via `parse_eml_isolated()`, 8 isolation/bomb/crash tests passing (`test_parser_isolation.py`), 0% golden drift across 21 scoring cases and 14 EML fixtures. |
| **HZ8** | **Reproducibility fields in `AnalysisRunConfig`** | **Implemented** | Enhanced `AnalysisRunConfig` with explicit `llm` envelope fields (`model`, `digest`, `quantization`, `num_ctx`, `options_hash`, `prompt_version`, `schema_version`), canonical deterministic hashing (`compute_options_hash()`, `compute_reproducibility_fingerprint()`), database persistence via `AnalysisRun.config` JSON column and Alembic migration `0006_analysis_run_config.py`, dynamic live Ollama metadata resolution in `resolve_llm_reproducibility()`, tool endpoint `GET /api/v1/tool/investigations/{id}/reproducibility`, 4 unit/integration tests passing (`test_analysis_run_reproducibility.py`), 0% golden drift. |
| **HZ9** | **Injection tests, release plan, documentation** | **Implemented** | Copilot prompt-injection resistance test suite covering direct override, system directive spoofing, role confusion, exfiltration, and benign injection discussion robustness (`test_injection_resistance.py`), two-phase offline acceptance test script (`scripts/offline_acceptance_test.py`, `.bat`, `.ps1`), production release plan and operational runbook (`docs/RELEASE_PLAN.md`), DEC-009 logged, 100% byte-for-byte golden regression fidelity, 434 tests passing across all test suites. |

---

## 3. Regression Corpus Coverage

The safety net verified by `scripts/check_golden` covers:
- **17 Hand-Built Scoring Cases + Variations**:
  - Clean baseline (0 pts, LOW)
  - Evidence-only (0 pts, raw 0.0)
  - Single weak finding (SPF_FAIL: 2 pts, LOW)
  - Multipliers (Weak 0.5x, Moderate 1.0x, Strong 1.5x)
  - Category cap enforcement (Authentication cap 16)
  - Theoretical maximum score (166 raw -> 100 pts, CRITICAL)
  - Severity boundaries (LOW, MEDIUM, HIGH, CRITICAL)
  - Critical Floor CF-01 (Lookalike domain + explicit same-brand claim -> HIGH)
  - Critical Floor CF-02 (Executive impersonation + financial request -> HIGH)
  - Critical Floor CF-03 (Credential phishing link + identity anomaly -> HIGH)
  - Critical Floor CF-04 (Suspicious attachment + identity anomaly -> HIGH)
  - Critical Floor CF-05 (Confirmed malicious indicator Strong -> HIGH, MALICIOUS)
  - Critical Floor CF-06 (Qualified routing fabrication -> HIGH)
  - Regression 13b (CF-06 negative / clean routing does not trigger CF-06)
  - CF-01 near-miss (Brand A lookalike + Brand B claim does not trigger CF-01)
  - Golden Scenarios (BENIGN, SUSPICIOUS, MALICIOUS, INDETERMINATE)
- **14 Email Fixtures (Forensics & E2E Pipeline)**:
  - 5 Canonical End-to-End Emails (`clean_legit_corporate`, `bec_ceo_wire_transfer`, `credential_harvesting_portal`, `protected_brand_lookalike`, `double_extension_macro`)
  - 6 Frozen Synthetic Hop-0 Cases (`legit_gmail_to_gmail`, `legit_m365`, `legit_forwarded_via_unknown_relay`, `adversarial_temporal_contradiction`, `adversarial_structural_implausibility`, `adversarial_independent_trusted_contradiction`)
  - 3 Routing Edge Cases (`no_received_chain`, `no_trusted_boundary_at_hop0`, `generic_malformed_header`)
