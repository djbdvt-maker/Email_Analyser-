#!/usr/bin/env bash
# ==============================================================================
# HopZero One-Click Native Launcher (Linux / macOS)
# ==============================================================================
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

python3 "$SCRIPT_DIR/scripts/launch.py" "$@"
