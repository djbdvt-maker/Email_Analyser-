# Contributing to HopZero

Thank you for contributing to HopZero Email Forensics & BotChain Tool Suite!

---

## 1. Golden Baseline Invariant (Zero Score Drift)
HopZero uses a deterministic qualification compiler and golden regression suite.
**Every pull request must maintain 100% byte-for-byte exact matches against `05_QA/golden/golden_outputs.json`**.
Before opening a PR, always verify:
```bash
python scripts/check_golden.py
```
If you intentionally update qualification rules or add test fixtures, update the baseline with explicit rationale recorded in `docs/DECISIONS.md`:
```bash
python scripts/save_golden.py
```

---

## 2. Development Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/djbdvt-maker/Email_Analyser-.git
   cd Email_Analyser-
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.lock
   ```
3. Install frontend dependencies:
   ```bash
   cd 04_FRONTEND && npm ci && cd ..
   ```
4. Verify system diagnostics:
   ```bash
   python scripts/doctor.py
   ```

---

## 3. Pull Request Checklist
Before submitting a PR, verify all steps pass:
- [ ] `python -m compileall -q 01_REGISTRY 02_FORENSICS 03_BACKEND hopzero scripts`
- [ ] `python scripts/check_golden.py` (Must match byte-for-byte)
- [ ] `python scripts/offline_acceptance_test.py`
- [ ] `python scripts/scan_secrets_and_pii.py`
- [ ] `cd 04_FRONTEND && npm run build`
- [ ] `python -m pytest -q` (All tests must pass)
- [ ] Record any architectural decisions in `docs/DECISIONS.md`.
