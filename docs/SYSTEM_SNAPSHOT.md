# System Snapshot & Baseline Specification

This document captures the verified environment specifications, tool versions, and regression baselines for the HopZero commercial-ready release pipeline.

---

## 1. Environment & Runtime Versions

| Component | Target / Installed Version | Architecture / Notes |
| :--- | :--- | :--- |
| **Python** | `3.12.10` | 64-bit AMD64 (`MSC v.1942`) |
| **Node.js** | `v24.20.0` | Frontend build and bundling environment |
| **npm** | `11.19.0` | Package manager |
| **PostgreSQL** | `16-alpine` (Range: `15.x` – `17.x`) | Enterprise Server edition backing store |
| **SQLite** | `3.45.3+` (Python 3.12 stdlib) | Zero-config Lite / Standard desktop edition store |
| **Ollama** | `0.33.3` | Local AI inference daemon |
| **Docker** | `29.8.1` (build `4a63305`) | Container runtime (optional, non-Docker native runs supported) |

---

## 2. Shared Resident LLM Model

| Parameter | Recorded Value |
| :--- | :--- |
| **Model Name** | `hermes3:3b` |
| **Exact Digest** | `sha256:a8851c5041d400c8eece484771e0a9f438e6500de9f22150ef2863bf7209fbd9` |
| **Format** | `gguf` |
| **Model Family** | `llama` |
| **Parameter Size** | `3.2B` |
| **Quantization** | `Q4_K_M` |
| **VRAM Footprint** | `< 2.5 GB` resident (tested on RTX / integrated fallback) |
| **Context Length** | `131,072` tokens |
| **Resident Provider** | Ollama daemon at `http://127.0.0.1:11434` |
| **Offline Fallback** | Deterministic rule-based forensic generator active if daemon is unavailable |

---

## 3. Regression Corpus & Golden Output Baseline

- **Golden Corpus Artifact**: `05_QA/golden/golden_outputs.json`
- **Scoring Cases**: 21 deterministic hand-crafted and synthetic edge cases
- **Raw Email Fixtures**: 14 standard RFC 5322 EML fixtures
- **Verification Script**: [`scripts/check_golden.py`](file:///c:/Users/HELLO/Desktop/sih/scripts/check_golden.py) (exits 0 on 100% byte-for-byte exact match)
- **Snapshot Generator Script**: [`scripts/save_golden.py`](file:///c:/Users/HELLO/Desktop/sih/scripts/save_golden.py)
- **Verification Status**: **100% byte-for-byte identical**. Zero drift.

---

## 4. Architectural Invariants Enforced

1. **LLM Scoring Authority**: 0 (deterministic engine strictly governs all 0–100 numerical risk scoring).
2. **Critical Score Floors**: CF-01 through CF-06 immutable.
3. **Action Governance**: All external remediation actions default to draft status awaiting human confirmation.
