#!/usr/bin/env bash
# ==============================================================================
# HopZero Remote Multi-Network Launcher (Linux / macOS)
# Enables secure public HTTPS tunnel for remote laptops on different networks.
# ==============================================================================
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

python3 "$SCRIPT_DIR/scripts/launch.py" --remote "$@"
