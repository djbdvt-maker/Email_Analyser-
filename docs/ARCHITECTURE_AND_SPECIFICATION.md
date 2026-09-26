# HopZero — Authoritative Architecture & Specification Manual

## Overview
HopZero is a deterministic email forensics and automated threat analysis engine built on the principle:
$$\text{Evidence} \neq \text{Finding} \neq \text{Score} \neq \text{Severity / Floor} \neq \text{Verdict} \neq \text{Enforcement}$$

---

## 1. The 41 Forensic Qualification Rules (Q1–Q41)
All 41 qualifications derive authoritatively from the single source of truth at `01_REGISTRY/releases/registry-v1.json` (SHA-256 verified).

### Tier 1: Critical Direct Threat Indicators (Base Weights 20–24)
- **`CONFIRMED_MALICIOUS_INDICATOR`** (Base Weight: 24, Threat Intelligence): Exact match against verified malicious threat intelligence IOCs.
- **`CREDENTIAL_PHISHING_LINK`** (Base Weight: 22, URL): Direct credential harvesting target URL or phishing kit structure.
- **`ROUTING_FABRICATION_QUALIFIED`** (Base Weight: 20, Routing): Qualified routing fabrication established by temporal contradiction beyond tolerance, independent trusted contradiction (Q40), or structural implausibility (Q41).

### Tier 2: High-Confidence Contextual Indicators (Base Weights 13–16)
- **`EXECUTIVE_IMPERSONATION`** (Base Weight: 16, Identity)
- **`EXECUTABLE_IN_ARCHIVE`** (Base Weight: 16, Attachment)
- **`EXPLICIT_BRAND_REPRESENTATION_CLAIM`** (Base Weight: 15, Identity)
- **`IDENTITY_ANOMALY`** (Base Weight: 15, Identity)
- **`PROTECTED_BRAND_LOOKALIKE_DOMAIN`** (Base Weight: 15, Domain)
- **`SUSPICIOUS_ATTACHMENT`** (Base Weight: 14, Attachment)
- **`PROTECTED_BRAND_LOOKALIKE_URL`** (Base Weight: 13, URL)

### Tier 3: Supporting Technical Anomaly Indicators (Base Weights 5–9)
- **`HOMOGLYPH_DOMAIN_MATCH`** (Base Weight: 9, Domain)
- **`BULLETPROOF_HOSTING_MATCH`** (Base Weight: 9, Infrastructure)
- **`FINANCIAL_REQUEST`** (Base Weight: 8, Social Engineering)
- **`DMARC_FAIL`** (Base Weight: 8, Authentication)
- **`IDENTIFIER_ALIGNMENT_FAILURE`** (Base Weight: 8, Authentication)
- **`LINK_DISPLAY_HREF_MISMATCH`** (Base Weight: 8, URL)
- **`KNOWN_BAD_ASN`** (Base Weight: 8, Infrastructure)
- **`MIXED_SCRIPT_DOMAIN`** (Base Weight: 7, Domain)
- **`EXTENSION_MIME_MISMATCH`** (Base Weight: 7, Attachment)
- **`MACRO_ENABLED_DOCUMENT`** (Base Weight: 7, Attachment)
- **`SPF_FAIL`** (Base Weight: 6, Authentication)
- **`DKIM_FAIL`** (Base Weight: 6, Authentication)
- **`DOUBLE_COMPOUND_EXTENSION`** (Base Weight: 6, Attachment)
- **`NEWLY_REGISTERED_DOMAIN`** (Base Weight: 5, Domain)
- **`NEWLY_OBSERVED_INFRASTRUCTURE`** (Base Weight: 5, Infrastructure)

### Evidence-Only Qualifications (16 total, Base Weight: 0)
`GENERIC_SUSPICION`, `IDENTITY_DISPLAY_NAME_MISMATCH`, `IDENTITY_REPLY_TO_MISMATCH`, `IDENTITY_RETURN_PATH_MISMATCH`, `DMARC_NONE`, `SPF_NONE`, `DKIM_NONE`, `PUNYCODE_DOMAIN_INDICATOR`, `URL_SHORTENER_DETECTED`, `AUTH_LIKE_PATH_DETECTED`, `URGENCY_AUTHORITY_FILENAME`, `ARCHIVE_TRUNCATED_OR_OVERSIZED`, `UNRESOLVABLE_REVERSE_DNS`, `CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE`, `CF-06:INDEPENDENT_TRUSTED_CONTRADICTION`, `CF-06:STRUCTURAL_IMPLAUSIBILITY`.

---

## 2. Six Forensic Confidence Floor Rules (CF-01 through CF-06)
Confidence floors raise the final severity floor to **`HIGH`** without modifying numeric points:
- **CF-01**: Protected-brand lookalike domain + explicit same-brand representation claim $\to$ minimum `HIGH`.
- **CF-02**: Executive impersonation + financial/payment request $\to$ minimum `HIGH`.
- **CF-03**: Credential-phishing link + qualifying identity anomaly $\to$ minimum `HIGH`.
- **CF-04**: Suspicious attachment + qualifying sender/security-context anomaly $\to$ minimum `HIGH`.
- **CF-05**: Exact confirmed malicious indicator $\to$ minimum `HIGH` and `MALICIOUS` verdict.
- **CF-06**: Qualified routing fabrication $\to$ minimum `HIGH`.

Negative Invariant: SPF/DKIM/DMARC failures, unfamiliar domains, missing Received headers, unknown relays, generic malformedness, and AI suspicion NEVER trigger a confidence floor automatically.

---

## 3. Locked 9-Bucket Score Engine
Theoretical Raw Maximum = 166.
- **Identity**: Cap 20
- **Authentication**: Cap 16
- **Domain**: Cap 16
- **URL**: Cap 22
- **Attachment**: Cap 20
- **Infrastructure**: Cap 14
- **Routing**: Cap 20
- **Social Engineering**: Cap 14
- **Threat Intelligence**: Cap 24

Multipliers: `Weak` = 0.5x, `Moderate` = 1.0x, `Strong` = 1.5x. Evidence-only = 0x.
Normalization formula:
$$\text{Final Score} = \text{clamp}\left(\text{round}\left(\frac{\text{Raw Score}}{166} \times 100\right), 0, 100\right)$$
Score Severity:
- 0–29: `LOW`
- 30–54: `MEDIUM`
- 55–74: `HIGH`
- 75–100: `CRITICAL`

$$\text{Final Severity} = \max(\text{Score Severity}, \text{Highest Floor Severity})$$

---

## 4. Canonical Verdict Model (Conclusion Generator)
The Conclusion Generator is strictly decoupled from the Score Engine:
1. `BENIGN`: Zero suspicious findings or baseline compliant.
2. `SUSPICIOUS`: Meaningful suspicious anomalies or floors CF-01, CF-02, CF-03, CF-04, CF-06 triggered.
3. `MALICIOUS`: Confirmed malicious threat intelligence (CF-05).
4. `INDETERMINATE`: Missing critical transmission evidence prevents reliable classification.

Crucial Invariants:
- `HIGH` or `CRITICAL` severity does NOT automatically mean `MALICIOUS`.
- User feedback does NOT force a `MALICIOUS` verdict.
- Only verified evidence determines the verdict.

---

## 5. AI Trust Boundary
AI may assist semantic extraction (e.g. identifying financial requests or brand representation claims in natural text).
AI MUST NOT own:
- Numeric scores
- Severity thresholds
- Confidence floors
- Final verdicts
- Threat enforcement authorization

All AI candidate proposals must pass:
1. Schema validation
2. Qualification validation (restricted to the 5 registry-eligible qualifications)
3. Grounding check (must reference verbatim text present in the email)
4. Deterministic corroboration & validity requirements (disqualifiers check)
5. Strength rule assignment (deterministic strength assignment)
6. Deduplication

---

## 6. User-Guided Re-Analysis Workflow
If HopZero initially scores an email as low risk and a user believes it to be phishing or spam:
1. **User Feedback Recorded**:
   - `UserFeedback` entity persisted (`SPAM_REPORTED`, `PHISHING_REPORTED`, `ANALYSIS_DISPUTED`).
   - Audited with `USER_FEEDBACK_SUBMITTED`.
   - **Feedback is an input to investigation processing, NOT a verdict.**
   - Feedback NEVER directly mutates scores, severities, or verdicts.
2. **Re-Analysis Execution**:
   - Creates a **NEW** `AnalysisRun`.
   - The original `AnalysisRun` remains completely immutable.
   - Runs full forensic analysis pipeline on the original immutable artifact.
   - Facts and findings are scoped to the new run.
   - Scores and conclusions are computed deterministically.
   - `inv.current_analysis_run_id` is updated **ONLY** if the new run successfully completes (`COMPLETED`).
   - Failed or cancelled runs never become current.
3. **Comparative Analysis**:
   - Canonical endpoint `/api/v1/investigations/{id}/compare-runs?run1={id}&run2={id}` provides score deltas, severity changes, verdict changes, and new findings.

---

## 7. Threat Response & Provider-Neutral Enforcement Abstraction
Enforcement is provider-neutral and decoupled from proprietary vendor APIs:
- Interface: `EnforcementProvider` (`block_sender`, `block_domain`, `block_ip`, `quarantine`).
- Default: `MockLocalEnforcementProvider` (clearly labeled demo provider).
- **Target Normalization & Grounding**:
  - Sender: lowercase, trimmed, RFC 5322 structure validated.
  - Domain: lowercase, trimmed, format validated.
  - IP: parsed via `ipaddress`. Unsupported targets (loopback, private RFC 1918, link-local, multicast, 0.0.0.0) are strictly rejected.
  - Grounding: arbitrary targets from user text not observed in the investigation's forensic evidence are rejected with HTTP 400.
- **Explicit Lifecycle States**:
  $$\text{REQUESTED} \longrightarrow \text{AUTHORIZED} \longrightarrow \text{EXECUTED / FAILED / REJECTED}$$
- **UI Integrity**:
  - Distinguishes `"Enforcement requested"` from `"External provider successfully blocked"`.
  - Never masquerades a local demo block as modifying external M365 or Google Workspace tenants.
- **RBAC**:
  - Only `ANALYST` or `ADMIN` roles can authorize, execute, or reject enforcement actions.
  - AI and score engine cannot authorize enforcement.
  - User feedback alone cannot directly block.

---

## 8. Verifiable Audit Trail
All operations are appended to the immutable `audit_events` table:
- `USER_FEEDBACK_SUBMITTED`
- `REANALYSIS_REQUESTED`
- `ANALYSIS_RUN_CREATED`
- `ANALYSIS_RUN_STATUS_CHANGED`
- `FINDING_PERSISTED`
- `SCORE_CONCLUSION_PERSISTED`
- `ENFORCEMENT_REQUESTED`
- `ENFORCEMENT_AUTHORIZED`
- `ENFORCEMENT_EXECUTED`
- `ENFORCEMENT_FAILED`
- `ENFORCEMENT_REJECTED`

Every event preserves the actor user ID, organization ID, timestamps, and structured metadata.
