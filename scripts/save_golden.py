#!/usr/bin/env python3
"""
scripts/save_golden.py
Generates and saves the golden baseline outputs for all regression corpus cases and email fixtures.
Writes directly to 05_QA/golden/golden_outputs.json.
"""
import sys
import os

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if os.path.dirname(__file__) not in sys.path:
    sys.path.insert(0, os.path.dirname(__file__))

from golden_runner import save_golden_snapshot

if __name__ == "__main__":
    save_golden_snapshot()
    sys.exit(0)
