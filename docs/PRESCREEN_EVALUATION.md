# HopZero Pre-Screen Layer Evaluation Report (F5)

This benchmark compares pre-screening architectures against labeled email samples to evaluate
whether candidate classifiers safely achieve computational savings without missing semantic threats.

| Strategy | Samples | Threat Recall | False Skips | LLM Savings | Latency (p50) | Latency (p95) | Memory Overhead |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Always-LLM (Safe Default)** | 8 | 100.0% | 0 | 0.0% | 0.01 ms | 0.01 ms | 0 MB (Native) |
| **Deterministic Heuristic Gate** | 8 | 100.0% | 0 | 50.0% | 0.006 ms | 0.015 ms | < 1 MB (Native) |
| **Laya Zero-Shot (Optional Extra)** | 8 | 25.0% | 3 | 37.5% | 38.5 ms | 38.5 ms | ~550 MB (PyTorch + Checkpoint) |

## Key Findings & Architectural Decision (HZ-F5)

1. **Safety First**: The primary risk of pre-screen AI skipping is a **false negative skip**—failing to send a novel semantic attack (e.g. CEO gift card lure or multilingual wire fraud) to the AI Reasoner.
2. **Zero-Shot Limitations**: Laya and lightweight zero-shot models show reduced recall on non-English scripts (Hindi, Kannada) and short executive impersonation lures without domain-specific fine-tuning.
3. **Safe Default**: `laya_prescreen_skip_ai_on_benign=False` must remain disabled by default in production. Skipping the LLM is only appropriate when explicit fine-tuning achieves >= 99.5% recall on organization-specific corpora.
4. **Lightweight Core**: Core installation excludes PyTorch (~550 MB), keeping the HopZero installer fast and portable. Laya is maintained as an optional extra (`pip install -e '.[laya]'`).