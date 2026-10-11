#!/usr/bin/env python3
"""
scripts/test_network_isolation.py
Offline Air-Gapped Network Isolation Test.
Monkeypatches the socket layer to intercept and block ANY outbound network call
to any non-localhost destination (only 127.0.0.1, ::1, and localhost permitted).
Under this strict network jail, verifies that the full forensic pipeline, parser,
score engine, and tool API execute completely without network leaks.
"""
import sys
import os
import socket
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "01_REGISTRY"))
sys.path.insert(0, str(REPO_ROOT / "02_FORENSICS"))
sys.path.insert(0, str(REPO_ROOT / "03_BACKEND"))

_orig_connect = socket.socket.connect
ALLOWED_HOSTS = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}


def patched_connect(self, address):
    host = address[0] if isinstance(address, tuple) else address
    # Allow localhost / loopback
    if host in ALLOWED_HOSTS or host.startswith("127."):
        return _orig_connect(self, address)
    raise PermissionError(
        f"[AIR-GAP VIOLATION] Attempted outbound network access to {address} during offline test!"
    )


def run_offline_isolation_test() -> bool:
    print("=" * 76)
    print("           HOPZERO AIR-GAPPED OFFLINE NETWORK ISOLATION TEST          ")
    print("=" * 76)

    # 1. Engage air-gap network jail
    socket.socket.connect = patched_connect
    print("[*] Outbound network jail ACTIVE: all non-localhost connections blocked.")

    try:
        # Test 2. Ensure connection to external internet raises PermissionError
        print("[Step 1] Verifying network jail traps external traffic...")
        blocked = False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("8.8.8.8", 53))
        except PermissionError:
            blocked = True
        assert blocked, "Network jail failed to block external IP!"
        print("    [OK] External traffic successfully trapped and blocked.")

        # Test 3. Verify local qualification registry loads without network
        print("[Step 2] Loading forensic registry under offline jail...")
        from hopzero.core.registry import load_registry
        reg = load_registry(verify_hash=True)
        assert len(reg) > 0
        print(f"    [OK] Registry loaded ({len(reg)} rules) with 0 network calls.")

        # Test 4. Run isolated parser on raw EML fixtures
        print("[Step 3] Parsing RFC 5322 EML fixtures under offline jail...")
        from hopzero.core.isolation import parse_eml_isolated
        fixture_dir = REPO_ROOT / "02_FORENSICS" / "tests" / "fixtures"
        eml_files = list(fixture_dir.glob("*.eml"))
        assert len(eml_files) > 0
        for eml in eml_files[:3]:
            raw_bytes = eml.read_bytes()
            canonical = parse_eml_isolated(raw_bytes, artifact_id=f"art-{eml.stem}")
            assert canonical is not None
            assert canonical.artifact_id
        print(f"    [OK] Successfully parsed {min(3, len(eml_files))} EML fixtures with 0 network calls.")

        # Test 5. Run deterministic score engine
        print("[Step 4] Running deterministic qualification compiler & score engine...")
        from app.services.score_engine import compute_score
        from dataclasses import dataclass
        @dataclass
        class MockFinding:
            id: str
            category: str
            strength: str
            qualification_code: str = ""
            normalized_target: str = ""
            normalized_subject_or_target: str = ""

        findings = [
            MockFinding("1", "Authentication", "Strong", "DMARC_FAIL"),
            MockFinding("2", "Authentication", "Strong", "SPF_FAIL"),
        ]
        res = compute_score(findings)
        assert res.total_score > 0
        print(f"    [OK] Deterministic score computed ({res.total_score}) with 0 network calls.")

        # Test 6. BotChain Tool Domain checker with local cache/heuristics
        print("[Step 5] Checking domain tool under offline jail...")
        from hopzero.tools.domain import analyze_domain
        res = analyze_domain("example.com")
        assert res is not None
        assert res.risk_verdict in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        print(f"    [OK] Domain tool ran with 0 outbound network calls (verdict: {res.risk_verdict}).")

        print("\n" + "=" * 76)
        print("          OFFLINE AIR-GAP TEST PASSED: ZERO NETWORK LEAKS             ")
        print("=" * 76)
        return True

    finally:
        # Restore original socket
        socket.socket.connect = _orig_connect


if __name__ == "__main__":
    success = run_offline_isolation_test()
    sys.exit(0 if success else 1)
