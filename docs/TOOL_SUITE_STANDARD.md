# HopZero Tool Suite Standard

**Version**: `1.0.0`  
**Status**: APPROVED & ACTIVE  
**Last Updated**: 2026-10-11

---

## 1. Overview & Purpose

The **HopZero Tool Suite Standard** establishes the architectural, operational, and contract specifications for all tools developed under the HopZero umbrella. 

Whether a tool operates standalone (e.g., Domain & Lookalike Checker, Infrastructure Analyzer, Routing Analyzer) or as part of the core email forensics platform, it must conform to this standard to ensure composability, security, and integration with **BotChain Studio** orchestration bots.

---

## 2. Invariant Adherence

Every tool in the HopZero suite must uphold the frozen core invariants:

1. **Facts → Findings → Conclusion → Verdict Separation**:
   Raw observations are preserved as immutable Facts. Evaluated criteria produce Findings. Syntheses produce Conclusions. High-level dispositions produce Verdicts. Every verdict must remain traceable back to original evidence.
2. **Deterministic Preference**:
   Never ask an LLM to establish a fact or verdict that deterministic code or curated data can establish more reliably.
3. **Zero Scoring Authority for LLMs**:
   LLMs have **0% scoring authority**. LLMs may propose semantic candidates or candidate observations, but these must pass complete deterministic qualification and corroboration funnels.
4. **Never an Automatic Irreversible Action**:
   Irreversible actions (blocking a domain, modifying DNS, deleting messages, quarantining assets) must **NEVER** execute automatically. Tools must create proposed actions as **Drafts** in `PENDING_CONFIRMATION` status, requiring explicit human authorization.
5. **Untrusted Input Markers**:
   All user-supplied and externally ingested content strings must be marked untrusted in OpenAPI documentation and API response bodies.
6. **Offline-First Acceptance**:
   Every tool must be fully testable and operational in an offline/air-gapped environment using deterministic fixtures. Network enrichments provide fresh intelligence, not structural prerequisites.

---

## 3. Required Endpoints Contract

Every tool in the suite must expose the following foundational endpoints:

### A. Discovery: `GET /tool-manifest`
* **Path**: `/tool-manifest` (and optionally `/api/v1/{tool_name}/manifest`)
* **Purpose**: Machine-readable tool specification consumed by BotChain Studio and agentic orchestrators.
* **Schema**:
```json
{
  "id": "hopzero-{tool-slug}",
  "name": "HopZero {Tool Title}",
  "version": "1.0.0",
  "description": "Short explanation of the tool's specialized forensic function.",
  "category": "security_forensics",
  "capabilities": ["capability_1", "capability_2"],
  "auth": {
    "type": "bearer",
    "header": "Authorization"
  },
  "limits": {
    "max_payload_size_bytes": 1048576,
    "timeout_seconds": 30.0
  },
  "operations": [
    {
      "name": "operation_name",
      "type": "coarse | fine | action",
      "description": "...",
      "method": "POST",
      "endpoint": "/api/v1/{tool-slug}/...",
      "parameters": {},
      "request_body": {},
      "response_schema": {}
    }
  ]
}
```

### B. Versioning: `GET /version`
* **Path**: `/version` (and optionally `/api/v1/{tool_name}/version`)
* **Purpose**: Returns the exact software versions, data release tags, and cryptographic hashes of all underlying datasets and registries.

### C. Health & Readiness: `GET /health`
* **Path**: `/health` (and optionally `/api/v1/{tool_name}/health`)
* **Response**: `{"status": "ok"}`

---

## 4. Operation Design & OpenAPI ID Convention

1. **Operation ID Prefixing**:
   Every operation in the OpenAPI schema must be explicitly prefixed with the tool identifier to prevent collisions during agent tool-binding:
   * Pattern: `{tool_slug}_{operation_name}` (e.g. `domain_check_domain`, `domain_get_manifest`, `hopzero_analyze_email`).
2. **Operation Types**:
   * **Coarse Operations**: High-level, synchronous execution taking raw input and returning a complete structured assessment.
   * **Fine Operations**: Granular sub-inspections querying specific aspects of an existing analysis without re-running entire pipelines.
   * **Action Operations**: Proposing remediation actions, always emitting `ActionDraft` objects requiring human confirmation.

---

## 5. Indicator & Entity Representation

Tools must exchange indicators using the standardized `NormalizedEntity` format from `hopzero.core.models`:

```python
@dataclass(frozen=True)
class NormalizedEntity:
    entity_type: str         # "sender" | "domain" | "ip" | "url" | "attachment" | "brand"
    normalized_value: str    # lowercased, stripped, canonical form
    raw_value: str           # verbatim original string
    provenance: dict         # source details: e.g. {"field": "from", "line": 42}
```

---

## 6. Verification & Test Suite Checklist

For any tool to be certified as part of the HopZero suite, it must include:
1. **Contract Tests**: Verifying manifest schema and version reporting.
2. **Offline Fixture Tests**: Validating all detection rules against frozen synthetic and real fixtures with zero network calls.
3. **Chain Tests**: Demonstrating end-to-end integration where output from one HopZero tool flows seamlessly into the inputs of another.
4. **Safety Net**: Passing with zero regression or score drift against the canonical golden baseline.
