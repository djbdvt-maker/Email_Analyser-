# HopZero Threat Model & Security Architecture

## 1. Scope & System Overview
HopZero is a digital forensics engine and analyst triage suite designed to ingest untrusted RFC 5322 email evidence, compute deterministic risk scores, generate auditable forensic packages, and provide AI-assisted explanations without granting autonomous action authority to LLMs.

---

## 2. Threat Actors & Attack Vectors

| Attacker Category | Goal | Attack Vector | HopZero Defense |
| :--- | :--- | :--- | :--- |
| **External Email Adversary** | Crash parser / DoS host system | MIME recursion bombs, infinite part nesting, multi-gigabyte attachments | **Subprocess Worker Wall** with resource caps: max 20 MIME depth, 250 parts, 10MB per part, 25MB total, 15s timeout. |
| **Adversarial Prompt Injector** | Manipulate score or exfiltrate system data | Hidden injection payloads in email body / headers ("IGNORE PREVIOUS INSTRUCTIONS") | **Zero LLM Scoring Authority**: Scores are computed 100% deterministically by the qualification compiler. Untrusted text is scrubbed at the 4-gate AI boundary. |
| **Hostile Network Actor** | Intercept or manipulate forensic communications | Man-in-the-middle attacks on external APIs | **100% Air-Gapped Readiness**: Works completely offline using local SQLite and resident Ollama instance with zero external cloud dependencies. |
| **Rogue / Compromised Bot** | Trigger unauthorized firewall or quarantine actions | Automated execution of remediation scripts | **ActionDrafts Governance**: All actions default to `PENDING` draft status requiring explicit human analyst sign-off. |

---

## 3. Trust Boundaries
1. **Untrusted Boundary (Input Ingestion)**:
   - Raw bytes (`.eml`, `.msg`, DOM reconstructed payloads from Chrome extension).
   - Sanitized via isolated subprocess worker before entering main application process.
2. **AI Reasoning Boundary (4-Gate Trust Boundary)**:
   - Untrusted candidate claims from LLM are validated against strict Pydantic schemas, critical score floor invariants, adversarial regex filters, and mandatory human review.
3. **Forensic Immutability**:
   - SHA-256 evidence hashing and immutable database audit logs.
