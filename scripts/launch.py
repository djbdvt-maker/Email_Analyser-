#!/usr/bin/env python3
"""
scripts/launch.py
HopZero One-Click Native Launcher.
- Auto-selects free ports for backend (8000+) and frontend (5173+).
- Verifies and warms up resident local LLM (Ollama / hermes3:3b).
- Runs database backup and startup migrations.
- Spawns backend & frontend services.
- Polls health endpoints with generous timeout.
- Opens default browser.
- Manages clean, graceful multi-process shutdown on exit.
"""
import os
import sys
import time
import socket
import signal
import subprocess
import webbrowser
import urllib.request
import json
import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "01_REGISTRY"))
sys.path.insert(0, str(REPO_ROOT / "02_FORENSICS"))
sys.path.insert(0, str(REPO_ROOT / "03_BACKEND"))

from hopzero.core.paths import get_app_data_root


def find_free_port(start_port: int, max_attempts: int = 50) -> int:
    """Finds the first available TCP port starting from start_port."""
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"Could not find an available port in range {start_port}-{start_port + max_attempts}")


def warmup_model(base_url: str = "http://127.0.0.1:11434", model: str = "hermes3:3b") -> bool:
    """Sends a lightweight zero-token ping to ensure the model weights are resident in RAM/VRAM."""
    try:
        data = json.dumps({"model": model, "prompt": "", "stream": False}).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            return resp.status == 200
    except Exception:
        return False


def wait_for_health(url: str, timeout_seconds: float = 45.0) -> bool:
    """Polls the backend health URL until it responds with 200."""
    start = time.time()
    while time.time() - start < timeout_seconds:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def main():
    parser = argparse.ArgumentParser(description="HopZero One-Click Native Launcher")
    parser.add_argument("--port", type=int, default=None, help="Backend port (default: auto-select 8000+)")
    parser.add_argument("--frontend-port", type=int, default=None, help="Frontend port (default: auto-select 5173+)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    parser.add_argument("--doctor", action="store_true", help="Run system doctor checks before starting")
    parser.add_argument("--remote", action="store_true", help="Enable secure public HTTPS tunnel for remote multi-network testing")
    parser.add_argument("--public-url", type=str, default=None, help="Custom public URL if hosted on a server or existing domain")
    args = parser.parse_args()

    print("=" * 76)
    print("                     HOPZERO ONE-CLICK LAUNCHER                       ")
    print("=" * 76)

    # Python version check
    v = sys.version_info
    if not (v.major == 3 and v.minor == 12):
        print(f"[!] Warning: Detected Python {v.major}.{v.minor}.{v.micro}.")
        print("    HopZero is certified on Python 3.12.x for binary wheel stability.")
        print("    To provision Python 3.12:")
        print("      Windows: winget install Python.Python.3.12")
        print("      macOS:   brew install python@3.12")
        print("      Linux:   sudo apt install python3.12 python3.12-venv")
        print("      uv:      uv python install 3.12 && uv venv --python 3.12\n")

    # 1. Doctor check if requested
    if args.doctor:
        from scripts.doctor import run_diagnostics, print_doctor_report
        checks = run_diagnostics()
        if not print_doctor_report(checks):
            print("\nDoctor checks failed. Resolve issues before launching.")
            sys.exit(1)

    # 2. Port allocation
    backend_port = args.port or find_free_port(8000)
    frontend_port = args.frontend_port or find_free_port(5173)
    print(f"[*] Allocating ports -> Backend: {backend_port} | Frontend: {frontend_port}")

    # 3. Model warm-up
    print("[*] Checking resident AI model warm-up...")
    if warmup_model():
        print("    [OK] hermes3:3b resident & warm in VRAM.")
    else:
        print("    [NOTE] Ollama resident model warming up or using deterministic offline fallback.")

    # 4. Remote Tunnel Setup (if requested)
    public_url = args.public_url or os.getenv("PUBLIC_URL")
    tunnel_proc = None
    processes = []

    if args.remote and not public_url:
        from scripts.tunnel import start_public_tunnel
        tunnel_proc, public_url = start_public_tunnel(backend_port)
        if tunnel_proc:
            processes.append(tunnel_proc)

    # 5. Environment setup
    env = os.environ.copy()
    env["PORT"] = str(backend_port)
    if public_url:
        env["PUBLIC_URL"] = public_url
        env["PORTAL_BASE_URL"] = public_url
        env["VITE_API_URL"] = public_url
    else:
        env["VITE_API_URL"] = f"http://localhost:{backend_port}"

    def shutdown(signum=None, frame=None):
        print("\n[*] Shutting down HopZero services cleanly...")
        for p in processes:
            try:
                p.terminate()
                p.wait(timeout=3.0)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        print("[*] HopZero shutdown complete. Goodbye!")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # 5. Launch Backend
    backend_dir = REPO_ROOT / "03_BACKEND"
    backend_cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(backend_port),
    ]
    print(f"[*] Starting Backend server on http://127.0.0.1:{backend_port}...")
    p_backend = subprocess.Popen(backend_cmd, cwd=str(backend_dir), env=env)
    processes.append(p_backend)

    # 6. Wait for Backend health
    health_url = f"http://127.0.0.1:{backend_port}/health"
    print(f"[*] Waiting for backend health check at {health_url}...")
    if wait_for_health(health_url, timeout_seconds=30.0):
        print("    [OK] Backend healthy and ready.")
    else:
        print("    [FAIL] Backend failed to report healthy within timeout!")
        shutdown()

    # 7. Launch Frontend
    frontend_dir = REPO_ROOT / "04_FRONTEND"
    frontend_cmd = [
        "npm.cmd" if sys.platform == "win32" else "npm",
        "run",
        "dev",
        "--",
        "--port",
        str(frontend_port),
    ]
    print(f"[*] Starting Frontend dev server on http://localhost:{frontend_port}...")
    p_frontend = subprocess.Popen(frontend_cmd, cwd=str(frontend_dir), env=env)
    processes.append(p_frontend)

    dashboard_url = f"http://localhost:{frontend_port}"
    print(f"\n============================================================================")
    print(f"  HopZero Forensic Platform is running:")
    print(f"  - SOC Admin Dashboard:  {dashboard_url}")
    print(f"  - Backend API:          http://127.0.0.1:{backend_port}")
    if public_url:
        print(f"  - 🌐 Remote Public URL:  {public_url}")
        print(f"  - 🌐 Employee Portal:    {public_url}/portal")
        print(f"  - 🌐 Extension Hub URL:  {public_url}")
    else:
        print(f"  - Employee Portal:      {dashboard_url}/portal")
    print(f"  - OpenAPI Docs:         http://127.0.0.1:{backend_port}/docs")
    print(f"  Press Ctrl+C to stop all services cleanly.")
    print(f"============================================================================\n")

    # 8. Open browser
    if not args.no_browser:
        time.sleep(1.5)
        webbrowser.open(dashboard_url)

    # 9. Supervise until Ctrl+C
    try:
        while True:
            time.sleep(1.0)
            if p_backend.poll() is not None:
                print("[!] Backend process exited unexpectedly.")
                break
            if p_frontend.poll() is not None:
                print("[!] Frontend process exited unexpectedly.")
                break
    except KeyboardInterrupt:
        pass
    finally:
        shutdown()


if __name__ == "__main__":
    main()
