"""
scripts/tunnel.py
Provides automatic zero-config secure public HTTPS tunneling via Cloudflare Quick Tunnel.
Allows employees on remote networks / laptops to connect to the local SOC Admin host.
"""
import os
import re
import sys
import time
import shutil
import logging
import threading
import subprocess
import urllib.request
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("hopzero.tunnel")

REPO_ROOT = Path(__file__).resolve().parent.parent
STORAGE_BIN = REPO_ROOT / "storage" / "bin"


def get_or_download_cloudflared() -> Optional[Path]:
    """Finds existing cloudflared binary or downloads portable binary for Windows."""
    # 1. System PATH
    system_path = shutil.which("cloudflared")
    if system_path:
        return Path(system_path)

    STORAGE_BIN.mkdir(parents=True, exist_ok=True)
    exe_name = "cloudflared.exe" if sys.platform == "win32" else "cloudflared"
    local_bin = STORAGE_BIN / exe_name

    if local_bin.exists():
        return local_bin

    # 2. Portable download for Windows
    if sys.platform == "win32":
        url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
        print(f"[*] Downloading portable cloudflared binary for remote multi-network access...")
        print(f"    Source: {url}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "HopZero-Launcher/1.0"})
            with urllib.request.urlopen(req, timeout=30.0) as resp, open(local_bin, "wb") as out:
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                chunk_size = 1024 * 1024
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    out.write(chunk)
                    downloaded += len(chunk)
                    if total > 0:
                        percent = (downloaded / total) * 100
                        print(f"\r    Downloading: {percent:.1f}% ({downloaded // (1024*1024)}MB / {total // (1024*1024)}MB)", end="", flush=True)
            print("\n    [OK] cloudflared downloaded successfully.")
            return local_bin
        except Exception as e:
            print(f"\n    [!] Failed to download cloudflared: {e}")
            if local_bin.exists():
                local_bin.unlink()
            return None

    return None


def start_public_tunnel(local_port: int, timeout_seconds: float = 30.0) -> Tuple[Optional[subprocess.Popen], Optional[str]]:
    """
    Spawns cloudflared tunnel pointing to local_port and extracts the public HTTPS URL.
    Returns (process, public_url).
    """
    bin_path = get_or_download_cloudflared()
    if not bin_path:
        print("[!] cloudflared binary not available. Remote public tunnel cannot be established.")
        return None, None

    cmd = [
        str(bin_path),
        "tunnel",
        "--url",
        f"http://127.0.0.1:{local_port}",
        "--no-autoupdate",
    ]

    print(f"[*] Starting secure Cloudflare HTTPS tunnel for port {local_port}...")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    public_url = None
    url_pattern = re.compile(r"https://[a-zA-Z0-9\-]+\.trycloudflare\.com")

    # Read stderr where cloudflared logs connection info
    start_time = time.time()
    captured_lines = []

    while time.time() - start_time < timeout_seconds:
        if proc.poll() is not None:
            print("[!] cloudflared process terminated unexpectedly.")
            break

        line = proc.stderr.readline()
        if not line:
            time.sleep(0.1)
            continue

        captured_lines.append(line.strip())
        match = url_pattern.search(line)
        if match:
            public_url = match.group(0)
            break

    # Background thread to drain remaining output without blocking
    def drain_pipe(pipe):
        try:
            for _ in pipe:
                pass
        except Exception:
            pass

    if proc.stderr:
        threading.Thread(target=drain_pipe, args=(proc.stderr,), daemon=True).start()
    if proc.stdout:
        threading.Thread(target=drain_pipe, args=(proc.stdout,), daemon=True).start()

    if public_url:
        print(f"    [OK] Secure Public Tunnel Active: {public_url}")
        return proc, public_url
    else:
        print("[!] Could not detect trycloudflare.com URL within timeout.")
        return proc, None
