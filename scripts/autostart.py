#!/usr/bin/env python3
"""
scripts/autostart.py
Configures optional "start at login" for HopZero:
- Windows: Windows Task Scheduler / User Run entry
- Linux: ~/.config/autostart/hopzero.desktop
- macOS: ~/Library/LaunchAgents/com.hopzero.agent.plist
"""
import sys
import os
import subprocess
import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def get_windows_command() -> str:
    python_exe = sys.executable
    launch_script = REPO_ROOT / "scripts" / "launch.py"
    return f'"{python_exe}" "{launch_script}" --no-browser'


def enable_autostart() -> bool:
    if sys.platform == "win32":
        task_name = "HopZeroForensics"
        cmd = get_windows_command()
        # Use schtasks for reliable user-session logon execution
        res = subprocess.run(
            ["schtasks", "/create", "/tn", task_name, "/tr", cmd, "/sc", "onlogon", "/f"],
            capture_output=True,
            text=True
        )
        if res.returncode == 0:
            print(f"[OK] Task Scheduler job '{task_name}' registered to start at user login.")
            return True
        else:
            print(f"[FAIL] schtasks failed: {res.stderr.strip()}")
            return False
    elif sys.platform == "darwin":
        plist_path = Path.home() / "Library" / "LaunchAgents" / "com.hopzero.forensics.plist"
        plist_path.parent.mkdir(parents=True, exist_ok=True)
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.hopzero.forensics</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{REPO_ROOT / 'scripts' / 'launch.py'}</string>
        <string>--no-browser</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"""
        plist_path.write_text(plist_content, encoding="utf-8")
        print(f"[OK] LaunchAgent written to {plist_path}")
        return True
    else:  # Linux
        desktop_dir = Path.home() / ".config" / "autostart"
        desktop_dir.mkdir(parents=True, exist_ok=True)
        desktop_file = desktop_dir / "hopzero.desktop"
        desktop_content = f"""[Desktop Entry]
Type=Application
Exec={sys.executable} {REPO_ROOT / 'scripts' / 'launch.py'} --no-browser
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name=HopZero Email Forensics
Comment=Deterministic Email Forensics & BotChain Tool Suite
"""
        desktop_file.write_text(desktop_content, encoding="utf-8")
        print(f"[OK] Autostart desktop entry written to {desktop_file}")
        return True


def disable_autostart() -> bool:
    if sys.platform == "win32":
        task_name = "HopZeroForensics"
        res = subprocess.run(
            ["schtasks", "/delete", "/tn", task_name, "/f"],
            capture_output=True,
            text=True
        )
        if res.returncode == 0:
            print(f"[OK] Task Scheduler job '{task_name}' successfully removed.")
            return True
        else:
            print(f"Task '{task_name}' was not found or already removed.")
            return True
    elif sys.platform == "darwin":
        plist_path = Path.home() / "Library" / "LaunchAgents" / "com.hopzero.forensics.plist"
        if plist_path.exists():
            plist_path.unlink()
            print(f"[OK] Removed {plist_path}")
        return True
    else:  # Linux
        desktop_file = Path.home() / ".config" / "autostart" / "hopzero.desktop"
        if desktop_file.exists():
            desktop_file.unlink()
            print(f"[OK] Removed {desktop_file}")
        return True


def check_status() -> bool:
    if sys.platform == "win32":
        task_name = "HopZeroForensics"
        res = subprocess.run(
            ["schtasks", "/query", "/tn", task_name],
            capture_output=True,
            text=True
        )
        enabled = res.returncode == 0
    elif sys.platform == "darwin":
        plist_path = Path.home() / "Library" / "LaunchAgents" / "com.hopzero.forensics.plist"
        enabled = plist_path.exists()
    else:
        desktop_file = Path.home() / ".config" / "autostart" / "hopzero.desktop"
        enabled = desktop_file.exists()

    status_str = "ENABLED" if enabled else "DISABLED"
    print(f"HopZero start-at-login status: {status_str}")
    return enabled


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Configure HopZero start-at-login")
    parser.add_argument("--enable", action="store_true", help="Enable start at user login")
    parser.add_argument("--disable", action="store_true", help="Disable start at user login")
    parser.add_argument("--status", action="store_true", help="Check current autostart status")
    args = parser.parse_args()

    if args.enable:
        enable_autostart()
    elif args.disable:
        disable_autostart()
    else:
        check_status()
