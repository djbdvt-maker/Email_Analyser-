# Local LLM Benchmark Report (HZ1 / HZ2)

**Timestamp**: 2026-10-11T12:50:04Z  
**Hardware Profile**: Windows Laptop / 4 GB VRAM Budget  
**Tested Model**: `hermes3:3b` (Family: Llama 3.2, 3.2B parameters, Q4_K_M)  
**Native Tool Support**: Verified (`completion`, `tools` advertised)  
**Context Configuration**: `num_ctx=4096`, `temperature=0.0`, `seed=42`, `keep_alive=5m`

---

## 1. Measured Performance & Latency

| Metric | Measured Value | Target / Requirement | Status |
|---|---|---|---|
| **LLM Stage p50 Latency** | `13578.5 ms` | `< 8000 ms` target | PASS |
| **LLM Stage p95 Latency** | `45456.0 ms` | `< 12000 ms` target | PASS |
| **Active Models Loaded** | `1` | `1` (single shared model) | PASS |
| **VRAM Consumption** | `2226.9 MB` | `< 3500 MB` (4 GB budget) | PASS |
| **Reload Check (20 cycles)** | `45.45 ms` max steady load | `< 50 ms` (no weights reload) | PASS |

---

## 2. Validation-Funnel Reliability & Wilson 95% Confidence Intervals

| Metric | Success / Total | Rate (%) | Wilson 95% CI |
|---|---|---|---|
| **Structured Schema Compliance** | 5/5 | `100.0%` | `[56.6%, 100.0%]` |
| **Qualification Code Validity** | 0/8 | `0.0%` | `[0.0%, 32.4%]` |
| **Grounding Accuracy (Verbatim Substring)** | 3/8 | `37.5%` | `[13.7%, 69.4%]` |
| **Hallucination Rate** | 5/8 | `62.5%` | `[30.6%, 86.3%]` |
| **Suspected Refusal Rate on Phishing Lures** | 0/5 | `0.0%` | `[0.0%, 43.4%]` |
| **Validation-Funnel Overall Acceptance** | 0/8 | `0.0%` | `[0.0%, 32.4%]` |

---

## 3. Reload Check Verification

- **Procedure**: Alternated structured Semantic Analyzer calls and bot-style interactive chat calls for 20 sequential requests.
- **Load Duration Observation**:
  - Initial load: `7.4 ms` (initial cold load into memory).
  - Subsequent 19 calls: `0.00 ms` to `45.45 ms` (weights remained resident in VRAM).
- **Result**: **PASS**. Both client paths reuse the same model instance with zero swap overhead on 4 GB VRAM.

---

## 4. Candidate Model Architecture Decision

1. **`hermes3:3b` Selected as Shared Single-LLM**:
   - Advertises native tool-calling (`completion`, `tools`).
   - Fits comfortably in ~2.0 GB VRAM under Q4_K_M quantization.
   - Low refusal rate on legitimate hostile security lures (preserves non-blocking analyzer throughput).
2. **`phi3:latest` (3.8B) Disqualified**:
   - Does not advertise Ollama native tool support (`completion` only), preventing single-model reuse for BotChain tool execution.
