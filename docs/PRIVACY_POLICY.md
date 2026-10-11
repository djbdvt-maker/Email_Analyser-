# HopZero Privacy Policy & Local Data Commitment

Last Updated: October 2026

## 1. Zero-Telemetry Architecture

HopZero is engineered from the ground up on a **Zero-Telemetry, Air-Gapped Local Invariant**.
- We do **not** collect your personal information.
- We do **not** collect telemetry, usage metrics, crash dumps, or error reports.
- We do **not** transmit parsed email messages, sender/recipient addresses, headers, IP locations, or AI inference prompts to any external cloud service or HopZero server.

---

## 2. Ingested Evidence & On-Premises Data Storage

1. **Local Database**: All email metadata, investigative logs, forensic qualification flags, and report drafts are stored locally on the investigator's host machine (by default in `%LOCALAPPDATA%\HopZero\hopzero.db` on Windows, `~/.local/share/hopzero/hopzero.db` on Linux, or `~/Library/Application Support/HopZero/hopzero.db` on macOS).
2. **Local AI Inference**: When AI reasoning is enabled, HopZero communicates strictly with a local Ollama instance running on `localhost:11434`. No email text or metadata leaves the loopback network interface.
3. **Encryption & Data Security**: Users are responsible for configuring local disk encryption (such as BitLocker, LUKS, or FileVault) to protect local SQLite databases and extracted forensic fixtures according to their internal data protection standards.

---

## 3. Sanitized Diagnostics Export

If you choose to export diagnostic logs using `python scripts/diagnostics.py --export` to share with your internal IT team or during a support request:
- HopZero runs an automated redaction engine that scrubs email addresses, external public IP addresses, JWT authentication tokens, and API credentials.
- The resulting `.zip` archive is saved locally on your filesystem for your prior review before any manual sharing.

---

## 4. Evidence Integrity & Legal Disclaimer

HopZero generates hash-verified, auditable evidence packages structured to support the applicable Section 63 Bharatiya Sakshya Adhiniyam (BSA) certification process; HopZero does not certify legal admissibility. Custody, handling, and preservation of personal data contained within evidentiary communications remain the sole responsibility of the investigating organization.
