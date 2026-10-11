"""
HopZero Two-Phase Offline Acceptance Test (HZ9)
================================================

Comprehensive acceptance test validating complete offline readiness,
zero score drift, strict architectural invariants, and BotChain tool contracts.

Phase 1: Static Integrity & Determinism Verification
  - Step 1.1: Qualification Registry SHA-256 integrity
  - Step 1.2: Compiler verification & qualification compilation
  - Step 1.3: Golden baseline regression (21 scoring cases + 14 EML fixtures)

Phase 2: Offline Pipeline, Isolation & Invariant Governance
  - Step 2.1: Parser isolation, recursion bomb defense & crash recovery
  - Step 2.2: Zero scoring authority & prompt injection resistance
  - Step 2.3: ActionDrafts governance (human confirmation required, 0 auto-execution)
  - Step 2.4: Reproducibility envelope & run configuration audit
  - Step 2.5: BotChain tool suite discovery, chaining & OpenAPI operation IDs

Usage:
  python scripts/offline_acceptance_test.py
"""

import os
import sys
import time
import subprocess
from pathlib import Path

# Ensure repo root and sub-packages are in sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
forensics_dir = str(REPO_ROOT / "02_FORENSICS")
if forensics_dir not in sys.path:
    sys.path.insert(0, forensics_dir)
backend_dir = str(REPO_ROOT / "03_BACKEND")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)


def log_phase(title: str):
    print("\n" + "=" * 78)
    print(f"  {title}")
    print("=" * 78)


def log_step(step_num: str, description: str):
    print(f"\n[Step {step_num}] {description}...")


def run_command(cmd: list[str], env=None) -> bool:
    start = time.time()
    res = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, capture_output=True, text=True)
    elapsed = time.time() - start
    if res.returncode == 0:
        print(f"  --> PASS ({elapsed:.2f}s)")
        return True
    else:
        print(f"  --> FAILED (exit code {res.returncode}, {elapsed:.2f}s)")
        if res.stdout:
            print("STDOUT:\n" + res.stdout[-800:])
        if res.stderr:
            print("STDERR:\n" + res.stderr[-800:])
        return False


def run_phase_1() -> bool:
    log_phase("PHASE 1: Static Integrity & Determinism Verification")

    # Step 1.1: Registry Verification
    log_step("1.1", "Checking Qualification Registry SHA-256 release hash")
    from hopzero.core.registry import load_registry
    try:
        reg = load_registry()
        print(f"  --> PASS (Loaded {len(reg['qualifications'])} qualifications with verified SHA-256)")
    except Exception as exc:
        print(f"  --> FAILED: Registry integrity error: {exc}")
        return False

    # Step 1.2: Compiler Verification
    log_step("1.2", "Verifying Compiler and qualification compilation")
    cmd_compiler = [sys.executable, "-m", "pytest", "01_REGISTRY/tests/test_compiler.py", "-q"]
    if not run_command(cmd_compiler):
        return False

    # Step 1.3: Golden Baseline Verification
    log_step("1.3", "Running Golden Baseline Regression (21 scoring cases + 14 EML fixtures)")
    cmd_golden = [sys.executable, "scripts/check_golden.py"]
    if not run_command(cmd_golden):
        return False

    return True


def run_phase_2() -> bool:
    log_phase("PHASE 2: Offline Pipeline, Isolation & Invariant Governance")

    # Enforce strictly offline environment
    offline_env = os.environ.copy()
    offline_env["HOPZERO_LLM_PROVIDER"] = "offline_deterministic_fallback"
    offline_env["LAYA_PRESCREEN_ENABLED"] = "False"

    # Step 2.1: Parser Isolation & Bomb Defense
    log_step("2.1", "Verifying Parser Isolation, MIME Recursion Bomb, and Timeout Recovery (HZ7)")
    cmd_isolation = [sys.executable, "-m", "pytest", "03_BACKEND/tests/test_parser_isolation.py", "-q"]
    if not run_command(cmd_isolation, env=offline_env):
        return False

    # Step 2.2: Injection Resistance & Invariant 1
    log_step("2.2", "Verifying Prompt Injection Resistance & Zero Scoring Authority (HZ9)")
    cmd_injection = [sys.executable, "-m", "pytest", "03_BACKEND/tests/test_injection_resistance.py", "-q"]
    if not run_command(cmd_injection, env=offline_env):
        return False

    # Step 2.3: ActionDrafts Governance (Invariant 7)
    log_step("2.3", "Verifying ActionDrafts Governance and Human-Confirmation Workflow (HZ4)")
    cmd_action_drafts = [sys.executable, "-m", "pytest", "03_BACKEND/tests/test_action_drafts.py", "-q"]
    if not run_command(cmd_action_drafts, env=offline_env):
        return False

    # Step 2.4: Reproducibility Envelope (HZ8)
    log_step("2.4", "Verifying Reproducibility Envelope in AnalysisRunConfig (HZ8)")
    cmd_repro = [sys.executable, "-m", "pytest", "03_BACKEND/tests/test_analysis_run_reproducibility.py", "-q"]
    if not run_command(cmd_repro, env=offline_env):
        return False

    # Step 2.5: BotChain Tool Suite & Multi-Tool Chaining (HZ3, HZ6)
    log_step("2.5", "Verifying BotChain Tool APIs, Operation IDs, and Multi-Tool Chaining")
    cmd_tools = [
        sys.executable,
        "-m",
        "pytest",
        "03_BACKEND/tests/test_tool_api.py",
        "03_BACKEND/tests/test_domain_tool.py",
        "03_BACKEND/tests/test_tool_chaining.py",
        "-q",
    ]
    if not run_command(cmd_tools, env=offline_env):
        return False

    return True


def main():
    print("=" * 78)
    print("      HOPZERO EMAIL FORENSICS - TWO-PHASE OFFLINE ACCEPTANCE TEST      ")
    print("=" * 78)
    t_start = time.time()

    p1_ok = run_phase_1()
    if not p1_ok:
        print("\n[ABORT] Phase 1 failed. Aborting acceptance test.")
        sys.exit(1)

    p2_ok = run_phase_2()
    if not p2_ok:
        print("\n[ABORT] Phase 2 failed. Aborting acceptance test.")
        sys.exit(1)

    elapsed_total = time.time() - t_start
    print("\n" + "=" * 78)
    print("                      ACCEPTANCE TEST VERDICT: SUCCESS                        ")
    print("=" * 78)
    print(f"Total time elapsed: {elapsed_total:.2f}s")
    print("All architectural invariants satisfied:")
    print("  [OK] INVARIANT 1: Zero LLM scoring authority (deterministic compiler)")
    print("  [OK] INVARIANT 2: 100% byte-for-byte golden regression fidelity (0 drift)")
    print("  [OK] INVARIANT 3: Bounded resource caps (parser timeout & recursion bombs)")
    print("  [OK] INVARIANT 4: 4-gate AI trust boundary & adversarial rejection")
    print("  [OK] INVARIANT 5: Zero automatic irreversible actions (ActionDrafts only)")
    print("  [OK] INVARIANT 6: Complete offline & air-gapped readiness")
    print("  [OK] INVARIANT 7: BotChain Tool Suite discovery & multi-tool chaining")
    print("=" * 78)
    sys.exit(0)


if __name__ == "__main__":
    main()
