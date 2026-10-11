<div align="center">

# 🚀 HopZero

**Air-Gapped Email Threat Forensics & BotChain Tool Suite**

[![Release](https://img.shields.io/badge/release-v4.2.0-blue.svg)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.12.10-green.svg)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Zero-Telemetry](https://img.shields.io/badge/telemetry-zero%20cloud%20leaks-success.svg)](docs/TELEMETRY.md)
[![Golden Regression](https://img.shields.io/badge/golden%20baseline-100%25%20byte--identical-success.svg)](05_QA/golden/golden_outputs.json)

[**Quickstart**](#-quickstart-per-os) • [**Architecture**](#-system-architecture) • [**5-Level Disclosure**](#-5-level-progressive-disclosure) • [**Support Matrix**](#-support-matrix) • [**Documentation**](docs/)

</div>

---

## 📖 Overview

**HopZero** is an enterprise-grade digital email forensics and incident response (DFIR) platform engineered for security operations center (SOC) analysts and digital investigators.

Unlike opaque cloud scanners or generative AI black-boxes, HopZero operates with **100% on-premises determinism**:
- **0 Cloud Leaks**: Completely functional in air-gapped environments without external network connections.
- **0 Score Drift**: Threat scoring is strictly computed by a compiled 41-rule qualification registry across 9 capped buckets.
- **0 LLM Scoring Authority**: Local LLM reasoning (`hermes3:3b`) serves strictly advisory roles through a 4-gate trust boundary; generative models cannot alter scores or trigger mitigation floors.
- **Auditable Evidence**: Produces hash-verified evidence packages structured to support the applicable Section 63 Bharatiya Sakshya Adhiniyam (BSA) / Section 65B Indian Evidence Act certification processes (*HopZero does not certify legal admissibility*).

---

## 🚀 Quickstart per OS

HopZero runs natively on bare metal—**no Docker required**.

### Windows (Command Prompt or PowerShell)
```cmd
git clone https://github.com/djbdvt-maker/Email_Analyser-.git hopzero
cd hopzero
hopzero.bat
```
*(Or in PowerShell: `.\hopzero.ps1`)*

### Linux (Ubuntu, Debian, RHEL)
```bash
git clone https://github.com/djbdvt-maker/Email_Analyser-.git hopzero
cd hopzero
chmod +x hopzero.sh
./hopzero.sh
```

### macOS (Apple Silicon / Intel)
```bash
git clone https://github.com/djbdvt-maker/Email_Analyser-.git hopzero
cd hopzero
chmod +x hopzero.sh
./hopzero.sh
```

### Universal Python Launcher
```bash
python scripts/launch.py
```

The launcher will:
1. Verify system prerequisites and auto-profile hardware.
2. Select conflict-free ports (Backend `8000+`, Frontend `5173+`).
3. Run embedded database migrations with automatic pre-upgrade backups.
4. Warm up local Ollama resident model (`hermes3:3b`).
5. Open your browser directly to the SOC investigation workspace.

---

## 🩺 System Diagnostics (`doctor`)

HopZero includes a self-healing diagnostic engine:
```bash
python scripts/doctor.py
```
Checks:
- Python 3.12.x pinned runtime & virtual environment.
- Node.js & Vite build artifacts.
- Disk capacity & app-data permissions.
- SQLite WAL mode & database connection.
- Ollama resident daemon and `hermes3:3b` model weights.
- Qualification registry cryptographic SHA-256 integrity.
- Golden regression baseline match.

---

## 🏗️ System Architecture

```
                                  UNTRUSTED INCOMING EVIDENCE
                                   (.eml / .msg MIME Files)
                                              │
                                              ▼
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                              SUBPROCESS PARSER SANDBOX                                     │
│  • Memory Limit: 100 MB       • Timeout: 15 seconds        • Archive Depth: <= 2          │
│  • Attachment Limit: <= 50    • Decompression Ceiling: 10 MB                               │
└─────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                              ▼
                                 NORMALIZED FORENSIC FACTS
                      (Header Lineage, Authentication, Extracted URLs)
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     ▼                                                 ▼
┌──────────────────────────────────────────┐     ┌──────────────────────────────────────────┐
│      DETERMINISTIC FORENSIC COMPILER     │     │       4-GATE TRUST BOUNDARY (LLM)        │
│  • 41-Rule Qualification Registry        │     │  • Resident Model: hermes3:3b            │
│  • 9 Capped Severity Buckets             │     │  • Context: 4096 tokens, temp=0.0        │
│  • Hard Category Floors (CF-01 .. CF-06) │     │  • Zero Scoring Authority Invariant      │
│  • Output: Exact Deterministic Score     │     │  • Output: Advisory Summary & Hypotheses │
└────────────────────┬─────────────────────┘     └─────────────────────┬────────────────────┘
                     └────────────────────────┬────────────────────────┘
                                              ▼
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                                 PROGRESSIVE DISCLOSURE UI                                 │
│  L1: Consumer Verdict  │  L2: Why & Action  │  L3: Technical Evidence                     │
│  L4: 41-Rule Findings  │  L5: Audit Trail & Section 63 BSA Evidence Package               │
└─────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                              ▼
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                              BOTCHAIN STUDIO TOOL SUITE APIs                              │
│  • hopzero_inspect_email_forensics  • hopzero_extract_artifacts  • hopzero_verify_dkim    │
│  • hopzero_score_threat             • hopzero_generate_action_drafts                      │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ 5-Level Progressive Disclosure

HopZero accommodates both non-technical users and courtroom forensic witnesses:

| Level | Target Audience | Primary Artifacts |
| :--- | :--- | :--- |
| **Level 1: Consumer Verdict** | End-users, Employees | Plain-English safety badge (`SAFE`, `SUSPICIOUS`, `DANGEROUS`), confidence score. |
| **Level 2: Why & Action** | Frontline Helpdesk, SOC T1 | Specific threat highlights, human-authorized `ActionDrafts` (quarantine, block). |
| **Level 3: Technical Evidence** | SOC Analysts, Incident Responders | Received-hop transit lineage, SPF/DKIM/DMARC matrix, lookalike domain distance. |
| **Level 4: 41-Rule Findings** | Senior Forensics, Engineers | Raw rule triggers, 9-bucket score breakdown, category floors, RFC anomalies. |
| **Level 5: Audit & Export** | Legal Counsel, Compliance, Court | Exact SHA-256 reproducibility fingerprint, custodial log, Section 63 BSA evidence bundle. |

---

## 💻 Support Matrix

### Operating Systems
- **Windows**: Windows 10 (21H2+), Windows 11, Windows Server 2022+ (x86_64)
- **Linux**: Ubuntu 22.04+, Debian 12+, RHEL/Rocky 9+ (x86_64, aarch64)
- **macOS**: macOS 13 Ventura, 14 Sonoma, 15 Sequoia (Apple Silicon M1-M4 & Intel x86_64)

### Hardware Editions
HopZero auto-detects host hardware and recommends an optimized edition:
- **Lite**: &lt;8 GB RAM or &lt;=4 CPU cores. WAL SQLite, aggressive pre-screening, offline deterministic fallback.
- **Standard**: 8–16 GB RAM, entry GPU or integrated graphics. WAL SQLite, resident Ollama `hermes3:3b`.
- **Pro**: &gt;=16 GB RAM, dedicated NVIDIA GPU (&gt;=4 GB VRAM). WAL SQLite / PostgreSQL, full GPU acceleration.
- **Server**: Multi-user headless server (&gt;=32 GB RAM). PostgreSQL database, enterprise worker pools.

---

## ⚠️ Known Limitations & Operational Bounds

To safeguard systems against malicious denial-of-service and parser exhaustion exploits, the following bounds are strictly enforced:
1. **MIME Archive Recursion**: Unpacking recursion depth is capped at `<= 2` nested archives.
2. **Decompression Ceiling**: ZIP and archive uncompressed size limit is capped at `10 MB`.
3. **Attachment Count**: A maximum of `50` attachments are extracted per email message.
4. **Single Local Model**: Inference is locked to `hermes3:3b` (`Q4_K_M`, 4096 ctx) to maintain low memory footprints and guarantee reproducibility across installations.

---

## 🔒 Security & Legal Governance

- **Vulnerability Disclosure**: Review [SECURITY.md](SECURITY.md) for triage SLAs and disclosure protocols.
- **Contributing Guidelines**: Review [CONTRIBUTING.md](CONTRIBUTING.md) for the mandatory zero-drift golden regression policy.
- **Threat Model**: Detailed STRIDE analysis documented in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- **Responsible Use**: Defensive incident response positioning detailed in [docs/RESPONSIBLE_USE.md](docs/RESPONSIBLE_USE.md).
- **Statutory Admissibility**: Hash-verified, auditable evidence packages are structured to support the applicable Section 63 BSA / Section 65B IEA certification process; *HopZero does not certify legal admissibility*. See [docs/TERMS_OF_SERVICE.md](docs/TERMS_OF_SERVICE.md).

---

## 📝 License

Distributed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for complete terms and third-party attributions.
