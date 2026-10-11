# HopZero Edition Specifications & Tier Breakdown

HopZero features four commercial hardware tiers tailored from lightweight field-investigation laptops up to distributed high-availability SOC server infrastructure.

---

## 📊 Feature & Capacity Comparison Matrix

| Feature / Capability | Lite | Standard (Default) | Pro | Server |
| :--- | :---: | :---: | :---: | :---: |
| **Target Hardware Profile** | &lt;8 GB RAM, &lt;=4 CPU cores | 8–16 GB RAM, Entry/iGPU | &gt;=16 GB RAM, &gt;=4 GB VRAM GPU | &gt;=32 GB RAM, Multi-Core Host |
| **Forensic Parser Sandbox** | Process Pool (100MB limit) | Subprocess Sandbox | Subprocess Sandbox | Parallel Worker Cluster |
| **Deterministic Scoring Compiler** | Full 41-Rule Engine | Full 41-Rule Engine | Full 41-Rule Engine | Full 41-Rule Engine |
| **9 Capped Scoring Buckets** | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **Category Floors (CF-01 .. CF-06)** | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **AI Advisory Reasoning** | Offline Fallback (Rule Facts) | Resident Ollama `hermes3:3b` | GPU-Accelerated `hermes3:3b` | Dedicated Local Model Host |
| **Database Engine** | Embedded SQLite (WAL mode) | Embedded SQLite (WAL mode) | SQLite / PostgreSQL | Enterprise PostgreSQL |
| **Concurrent Users / Seats** | 1 Analyst | 1–3 Analysts | 5–10 Analysts | Unlimited Multi-Tenant |
| **BotChain Tool APIs** | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **Section 63 BSA Evidence Package** | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **Automated Database Backups** | Local Pre-Upgrade Backup | Local Pre-Upgrade Backup | Point-in-Time WAL Backup | Automated Enterprise Replication |
| **Air-Gapped Network Isolation** | Strict Socket Jail | Strict Socket Jail | Strict Socket Jail | Strict Socket Jail |

---

## ⚙️ Edition Invariants

1. **Deterministic Forensics Identical Across All Editions**:
   No tier receives "better" or "different" risk scores. The 41-rule qualification registry, category floor logic, and mathematical capped scoring behave 100% identically on Lite as they do on Server.
2. **Single Shared Local Model Invariant**:
   Whenever AI reasoning is active, all editions pin Nous Research Hermes 3 3B (`hermes3:3b:latest`, Q4_K_M quantization, 4096 context window).
3. **No Network Telemetry**:
   All editions operate 100% on-premises with zero outbound cloud calls.
