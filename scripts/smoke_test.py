#!/usr/bin/env python3
"""
scripts/smoke_test.py
Clean-install smoke test that simulates a brand new user following the README:
1. Runs scripts/install.py --offline --yes
2. Starts backend service
3. Checks /health and /api/v1/system/edition
4. Stops service cleanly
"""
import sys
import os
import time
import socket
import subprocess
import urllib.request
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scripts.launch import find_free_port


def run_smoke_test() -> bool:
    print("=" * 76)
    print("                  HOPZERO CLEAN-INSTALL SMOKE TEST                    ")
    print("=" * 76)

    # 1. Run installer non-interactively
    print("[Step 1] Running installer (scripts/install.py -y --offline)...")
    res = subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "install.py"), "-y", "--offline"], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[FAIL] Installer failed:\n{res.stderr}\n{res.stdout}")
        return False
    print("    [OK] Installer completed successfully.")

    # 2. Select free port and start backend
    port = find_free_port(8800)
    print(f"[Step 2] Spawning backend server on 127.0.0.1:{port}...")
    backend_dir = REPO_ROOT / "03_BACKEND"
    env = os.environ.copy()
    env["PORT"] = str(port)

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(backend_dir),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    try:
        # 3. Poll /health
        health_url = f"http://127.0.0.1:{port}/health"
        print(f"[Step 3] Polling {health_url}...")
        healthy = False
        start = time.time()
        while time.time() - start < 20.0:
            try:
                with urllib.request.urlopen(health_url, timeout=1.0) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        if data.get("status") == "ok":
                            healthy = True
                            break
            except Exception:
                pass
            time.sleep(0.5)

        if not healthy:
            print("[FAIL] Backend did not respond healthy within timeout.")
            return False
        print("    [OK] /health responded with status: ok")

        # 4. Check system edition
        edition_url = f"http://127.0.0.1:{port}/api/v1/system/edition"
        print(f"[Step 4] Checking {edition_url}...")
        with urllib.request.urlopen(edition_url, timeout=2.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            edition = data.get("recommended_edition")
            assert edition in ("Lite", "Standard", "Pro", "Server"), f"Invalid edition {edition}"
            print(f"    [OK] System edition resolved: {edition}")

        # 5. Check tool manifest
        manifest_url = f"http://127.0.0.1:{port}/api/v1/tool/manifest"
        print(f"[Step 5] Checking {manifest_url}...")
        with urllib.request.urlopen(manifest_url, timeout=2.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert "HopZero Email Forensics" in data.get("name", ""), f"Unexpected manifest name {data.get('name')}"
            print(f"    [OK] BotChain tool suite manifest verified: {data.get('name')}")

        print("\n" + "=" * 76)
        print("                 SMOKE TEST PASSED: ALL CHECKS HEALTHY                ")
        print("=" * 76)
        return True

    finally:
        # Clean teardown
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    success = run_smoke_test()
    sys.exit(0 if success else 1)
