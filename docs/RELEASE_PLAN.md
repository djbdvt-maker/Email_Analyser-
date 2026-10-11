# HopZero Email Forensics & Tool Suite - Release Plan & Operational Runbook

**Release Version**: v2.0.0  
**Target Architecture**: Hardened Standalone Tool Suite & BotChain Studio Integration  
**Date**: 2026-10-11  
**Status**: APPROVED FOR PRODUCTION  

---

## 1. Executive Summary

HopZero has completed sequential hardening and refactoring across all 10 work packages (**HZ0–HZ9**). It operates as a dual-surface forensic platform:
1. **Interactive SOC Platform & Chrome Extension**: Analysts and users receive real-time email forensics, routing walk visualizations, deterministic scores, and human-confirmed mitigation actions.
2. **BotChain Studio Tool Suite**: Headless forensic micro-tools discoverable via standardized manifests (`GET /tool-manifest`), operating with clean operation IDs, zero LLM scoring authority, untrusted string demarcations, and draft-only action governance.

---

## 2. Locked Architectural Invariants Verification Matrix

| # | Invariant | Enforcement Mechanism | Status |
|---|---|---|:---:|
| **1** | **LLM Has 0 Scoring Authority** | The score is computed 100% deterministically from the compiled Qualification Registry (`01_REGISTRY/releases/registry-v1.json`). LLMs cannot award points, modify multipliers, or trigger critical floors directly. | **VERIFIED** |
| **2** | **Zero Golden Score Drift** | All 21 scoring regression cases and 14 EML fixtures pass 100% byte-for-byte via `scripts/check_golden.py`. | **VERIFIED** |
| **3** | **Actions Are Always Drafts** | Irreversible actions (threat blocks, quarantine) are proposed as `ActionDraft` rows with status `PENDING_CONFIRMATION`. Human analyst approval via `POST /confirm` is strictly required. | **VERIFIED** |
| **4** | **Subprocess Parser Isolation** | Untrusted RFC 5322 parsing runs in an isolated worker subprocess with a hard 15s timeout and resource caps (depth 20, max parts 250, 10MB per part, 25MB cumulative). | **VERIFIED** |
| **5** | **4-Gate AI Trust Boundary** | Untrusted model proposals pass through Gate 1 (qualification validation), Gate 2 (claim signature validation), Gate 3 (grounding validation), and Gate 4 (H2 semantic validity) before conversion to Findings. | **VERIFIED** |
| **6** | **Single Shared Local LLM** | Standardized on `hermes3:3b` resident in Ollama (< 4 GB VRAM) shared across semantic forensic extraction and tool orchestration. | **VERIFIED** |
| **7** | **Complete Offline Operation** | Zero mandatory external network dependencies. Seamless fallback to deterministic pattern matching when the LLM is offline or disabled. | **VERIFIED** |
| **8** | **Full Auditability & Provenance** | Every run records an immutable `AIExecutionProvenance` and `AnalysisRunConfig` reproducibility envelope (`model`, `digest`, `quantization`, `num_ctx`, `options_hash`). | **VERIFIED** |
| **9** | **Untrusted Content Demarcation** | Email bodies, subjects, and headers are explicitly labeled as untrusted strings across all JSON endpoints, preventing prompt injection into BotChain agent contexts. | **VERIFIED** |
| **10** | **Extension Workflow Preserved** | HopZero's Chrome Extension visual triage and background worker workflow remain 100% operational (24/24 extension tests passing). | **VERIFIED** |
| **11** | **OpenAPI Clean Namespace** | All operation IDs on the tool router are cleanly prefixed with `hopzero_*` or `hopzero_{tool}_*` with zero collisions. | **VERIFIED** |

---

## 3. BotChain Studio Integration Guide

### 3.1 Tool Discovery
- **Tool Root Manifest**: `GET /tool-manifest`
- **Domain Checker Manifest**: `GET /api/v1/domain/manifest`
- **System Version**: `GET /version`

### 3.2 Coarse Analysis Endpoint
- **URL**: `POST /api/v1/tool/analyze-email`
- **OperationId**: `hopzero_analyze_email`
- **Default Parameter**: `include_body=false` (prevents polluting agent LLM context window with raw untrusted text).
- **Response**: Immediate verdict (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`), numeric score, active risk floors, top 5 corroborated findings, and reproducibility metadata.

### 3.3 Fine Inspection Endpoints
- `GET /api/v1/tool/investigations/{id}/headers` (`hopzero_inspect_headers`)
- `GET /api/v1/tool/investigations/{id}/indicators` (`hopzero_extract_indicators`)
- `GET /api/v1/tool/investigations/{id}/explain-score` (`hopzero_explain_score`)
- `GET /api/v1/tool/investigations/{id}/summary` (`hopzero_get_investigation`)
- `GET /api/v1/tool/investigations/{id}/reproducibility` (`hopzero_inspect_reproducibility`)

### 3.4 Draft Proposal Endpoint
- `POST /api/v1/tool/investigations/{id}/propose-action` (`hopzero_tool_propose_action`)
- Creates an `ActionDraft` with `actor_via="botchain"` requiring human confirmation.

---

## 4. Operational Runbook

### 4.1 Prerequisites
- Python 3.12+
- PostgreSQL or SQLite
- Ollama with `hermes3:3b` resident (`ollama run hermes3:3b`)

### 4.2 Starting the Backend
```bash
cd 03_BACKEND
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 4.3 Running the Acceptance Verification
Run the two-phase offline acceptance test anytime before a release or deployment:
```bash
# Windows
scripts\offline_acceptance_test.bat

# PowerShell
.\scripts\offline_acceptance_test.ps1

# Python Direct
python scripts/offline_acceptance_test.py
```

### 4.4 Checking Golden Baselines
To verify zero score drift against the canonical forensic corpus:
```bash
python scripts/check_golden.py
```

---

## 5. Standalone Tool Extraction Roadmap

HopZero's architecture decouples forensic sub-capabilities into standalone tools adhering to `docs/TOOL_SUITE_STANDARD.md`:

1. **`hopzero-domain-checker` (v1.0.0, Extracted in HZ6)**:
   - Module: `hopzero/tools/domain/`
   - Detects brand lookalikes, homoglyphs, and punycode.
2. **`hopzero-ip-checker` (Planned)**:
   - Evaluates hop reputation, relay anomalies, and VPN/datacenter egress.
3. **`hopzero-attachment-inspector` (Planned)**:
   - Isolated recursive archive decompression and file type mismatch detection.
4. **`hopzero-url-checker` (Planned)**:
   - Suspicious path heuristics, redirect chain tracing, and credential portal detection.

---

## 6. Disaster Recovery & Rollback

- **Parser Hang / Crash**: Child worker process killed automatically at 15s; fallback `CanonicalEmail` generated with `is_truncated=True`; scoring engine proceeds with remaining deterministic signals.
- **LLM Out of Memory / Offline**: Automatic graceful fallback to `offline_deterministic_fallback`; zero penalty or bonus applied; exact status recorded in provenance.
- **Corrupted Registry**: `verify_registry_integrity()` halts initialization if `registry-v1.json` does not match `registry-v1.sha256`.
