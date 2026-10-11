# Security Policy

## Supported Versions

Only the latest release and current minor versions receive security updates:

| Version | Supported          |
| :---    | :---               |
| 4.2.x   | :white_check_mark: |
| 4.1.x   | :white_check_mark: |
| < 4.1   | :x:                |

---

## Reporting a Vulnerability

The HopZero Engineering Team takes software security and evidence integrity seriously.
If you discover a security vulnerability, parser sandbox escape, or prompt injection flaw:

1. **Do NOT open a public GitHub issue.**
2. Send an encrypted email or report to `security@hopzero.local`.
3. Include:
   - Vulnerability type and affected component (e.g. parser, authentication, LLM trust boundary).
   - Proof-of-concept `.eml` or reproduction script.
   - Output from `python scripts/diagnostics.py --export` (PII sanitized).
4. **SLA & Response Timeline**:
   - Initial acknowledgement: **Within 24 hours**.
   - Triage assessment and severity scoring: **Within 72 hours**.
   - Security patch release and CVE advisory: **Within 14 calendar days**.

---

## Security Boundaries & Design Invariants

HopZero enforces strict architectural invariants:
- **Zero LLM Scoring Authority**: Untrusted content can never manipulate threat scores.
- **Subprocess Worker Wall**: Raw RFC 5322 MIME messages are unpacked in isolated subprocess sandboxes with hard memory, depth, and timeout limits.
- **ActionDrafts Governance**: Irreversible remediation actions (quarantine, firewall rules) are created strictly as drafts requiring human SOC analyst authorization.
