# V4.1 Changelog — Full Implementation Pass

## Execution environment

This V4.1 pass was executed with full runtime verification against
Python 3.13 on Windows. All 253+ tests pass under `pytest -v`. The
frontend builds cleanly via `tsc && vite build`. Unlike previous
passes (V3, V4), this is **not** a "code-only, never-run" delivery.

**Test baseline confirmed:** 253 tests across 5 test suites
(01_REGISTRY: 2, 02_FORENSICS: 98, 03_BACKEND: 132+, 05_QA: 17, 06_N8N: 4).

---

## Phase 1: Registry Reconciliation & Bridge Fix

| Change | File(s) |
|---|---|
| Added `CREDENTIAL_PHISHING_LINK` qualification | `01_REGISTRY/source/qualifications.yaml` |
| Recompiled registry snapshot | `01_REGISTRY/releases/`, `01_REGISTRY/hopzero_registry/snapshot.py` |
| Updated forensics qualification bridge | `02_FORENSICS/hopzero_forensics/qualification_vocab.py` |

The registry now includes `CREDENTIAL_PHISHING_LINK` alongside the
existing 9 qualifications, making it available for the CF-03 floor
(credential phishing + identity anomaly).

## Phase 2: Trust Boundary & AI Service

| Change | File(s) |
|---|---|
| Added deterministic corroboration stage [5b] for `CREDENTIAL_PHISHING_LINK` | `app/services/trust_boundary_service.py` |
| Dynamic prompt vocabulary from registry | `app/services/ai_reasoner_service.py` |
| Added pattern matching for `EXECUTIVE_IMPERSONATION`, `EXPLICIT_BRAND_REPRESENTATION_CLAIM` | `app/services/ai_reasoner_service.py` |
| **CRITICAL FIX:** Removed overly broad credential link regex from offline fallback | `app/services/ai_reasoner_service.py` |

**Critical fix detail:** The `_extract_offline_fallback_candidates`
function contained a regex (`https?://[^\s]*(?:login|signin|verify|
password|auth)[^\s]*`) that over-matched, treating paths like
`/account/verify` as credential phishing links. This caused
`protected_brand_lookalike.eml` to incorrectly trigger CF-03 instead
of the expected CF-01. The regex was removed entirely — credential
phishing link detection belongs in the deterministic links analyzer,
not in the AI offline fallback.

## Phase 3: Conclusion Generator & Score Engine

| Change | File(s) |
|---|---|
| Created deterministic `ConclusionGenerator` | `app/services/conclusion_generator.py` (NEW) |
| Integrated conclusion into score engine | `app/services/score_engine.py` |
| Persists verdict fields | `app/services/score_engine_service.py` |
| Added verdict/one_line/why columns to ScoreConclusion | `app/models.py` |
| Updated response schemas | `app/schemas.py` |

**Floor priority order:** CF-05 > CF-06 > CF-03 > CF-02 > CF-04 > CF-01.
This ensures that specific attack vectors (confirmed malicious, routing
fabrication, credential phishing) take precedence over general domain
spoofing (CF-01).

**Verdict taxonomy:**
- `confirmed_malicious` (CF-05)
- `routing_fabrication` (CF-06)
- `credential_phishing` (CF-03)
- `bec_ceo_impersonation` (CF-02)
- `suspicious_attachment_malware_delivery` (CF-04)
- `spoofed_domain_typosquat` (CF-01)
- `likely_benign` (Clean severity, no floors)
- `suspicious_anomaly_detected` (Low/Medium severity, no floors)
- `suspicious_threat_detected` (High/Critical severity, no floors)

## Phase 4: Eliminate Fabricated Placeholders in Detail Response

| Change | File(s) |
|---|---|
| Persist envelope metadata (from/reply-to/return-path/subject/message-id/date) as Facts | `app/services/pipeline_service.py` |
| Persist received hops, extracted links, extracted attachments as Facts | `app/services/pipeline_service.py` |
| Rewrote detail response builder to read from persisted data | `app/services/investigation_service.py` |
| Auth results from fact types, not hardcoded | `app/services/investigation_service.py` |
| Default auth to `"unavailable"` not `"neutral"` | `app/services/investigation_service.py` |

**Key fix:** `EmailAddress` has no `.domain` attribute. Domain is now
computed from `from_addr.split("@")[-1].lower()`.

The detail response builder no longer generates ANY placeholder or
fabricated values. Every field is sourced from persisted Facts,
Findings, or ScoreConclusion rows.

## Phase 5: API Surface Reconciliation & Async Analysis

| Endpoint | Method | Status | File(s) |
|---|---|---|---|
| `/{id}/artifacts` | POST | 201 | `app/api/v1/routes_investigations.py` |
| `/{id}/artifacts` | GET | 200 | `app/api/v1/routes_investigations.py` |
| `/{id}/analyze` | POST | 202 (async) | `app/api/v1/routes_investigations.py` |
| `/{id}/audit` | GET | 200 | `app/api/v1/routes_investigations.py` |
| `/{id}/actions` | POST | 200 | `app/api/v1/routes_investigations.py` |

**Async analysis:** Uses `threading.Thread` with daemon=True. Worker
creates its own `SessionLocal()` DB session, runs the full pipeline
(parse → analyze → score), and closes cleanly. No Celery/Redis/Kafka.

**Role enforcement:** VIEWER role cannot perform analyst actions
(confirm, false_positive, reopen, escalate). Returns 403.

**List investigations:** Now populates `score`, `severity`, `verdict`
from the latest `ScoreConclusion` row.

## Phase 6: Evidence Export Bundle

| Change | File(s) |
|---|---|
| `export_artifact()` creates real zip bundle (artifact + manifest.json) | `app/services/evidence_service.py` |
| Updated test: export hash != raw content hash | `tests/test_evidence.py` |

The export bundle is a zip file containing the original artifact bytes
plus a `manifest.json` with filename, MIME type, original SHA-256, and
export timestamp. The `export_bundle_sha256` is now computed over the
zip bytes, which is different from `original_artifact_sha256` — fixing
the V3/V4 documented gap where the two hashes were identical.

## Phase 7: Frontend Reasoning Cleanup

| Change | File(s) |
|---|---|
| Fixed verdict mapping: `inv.title` → `inv.verdict ?? null` | `04_FRONTEND/src/services/api.ts` |
| Fixed score/severity mapping from backend response | `04_FRONTEND/src/services/api.ts` |
| Removed client-side verdict fabrication fallback | `04_FRONTEND/src/components/ProgressiveDisclosure/Level1ConsumerVerdict.tsx` |

The frontend now displays ONLY backend-authored verdicts. If no
verdict exists (analysis not yet run), it displays "Pending" — never
fabricates a verdict from severity.

## Phase 8: Documentation & Regression Tests

Added `tests/test_regression_v4.py` with comprehensive regression
coverage for:
- Conclusion generator verdicts (clean, floor-driven, severity-based)
- Verdict persistence in ScoreConclusion
- List investigations includes score/severity/verdict
- VIEWER role cannot perform analyst actions
- Artifact upload and listing
- Async analyze endpoint returns 202
- Audit trail endpoint
- Detail response contains no placeholder strings

---

## Corrections to V4 CHANGELOG claims

The following claims from V4_CHANGELOG.md have been resolved:

1. **Conclusion Generator was "STUBBED (interface only)"** →
   Now **IMPLEMENTED** with deterministic `ConclusionGenerator` class
   producing structured `ConclusionOutput(verdict, one_line, why)`.

2. **`export_bundle_sha256` produced same hash as original** →
   Now **FIXED** — export is a real zip bundle, hashes differ.

3. **CF-01 was "NOT IMPLEMENTED"** →
   Now **IMPLEMENTED** via `EXPLICIT_BRAND_REPRESENTATION_CLAIM` +
   `PROTECTED_BRAND_LOOKALIKE_DOMAIN` qualifications and corresponding
   floor evaluation.

4. **"I did not run pytest"** →
   All 253 tests **confirmed passing** in this delivery.

---

## Files changed in this pass

**New:**
- `app/services/conclusion_generator.py`
- `tests/test_regression_v4.py`

**Modified:**
- `01_REGISTRY/source/qualifications.yaml`
- `01_REGISTRY/releases/` (recompiled snapshot)
- `02_FORENSICS/hopzero_forensics/qualification_vocab.py`
- `app/models.py` — added `verdict`, `one_line_explanation`, `why_explanation` to `ScoreConclusion`
- `app/schemas.py` — added `AnalysisResponse`, `AuditEventOut`; updated `InvestigationOut`, `ScoreOut`
- `app/services/ai_reasoner_service.py` — removed overly broad credential link regex from offline fallback
- `app/services/trust_boundary_service.py` — added [5b] corroboration for `CREDENTIAL_PHISHING_LINK`
- `app/services/score_engine.py` — integrated `ConclusionGenerator`, added `_normalize_category()`
- `app/services/score_engine_service.py` — persists verdict fields
- `app/services/pipeline_service.py` — persists envelope metadata, hops, links, attachments as Facts
- `app/services/investigation_service.py` — rewrote detail builder, added role enforcement, added audit endpoint
- `app/services/evidence_service.py` — real zip bundle for export
- `app/api/v1/routes_investigations.py` — added artifacts, analyze, audit, actions endpoints
- `04_FRONTEND/src/services/api.ts` — fixed verdict/score/severity mapping
- `04_FRONTEND/src/components/ProgressiveDisclosure/Level1ConsumerVerdict.tsx` — removed client-side verdict fallback
- `tests/test_evidence.py` — updated export hash assertion
