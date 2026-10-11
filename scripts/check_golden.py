#!/usr/bin/env python3
"""
scripts/check_golden.py
Verifies that all regression corpus cases and email fixtures match the golden baseline byte-for-byte.
Exits with 0 on exact match, or 1 on diff / missing snapshot.
"""
import sys
import os

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if os.path.dirname(__file__) not in sys.path:
    sys.path.insert(0, os.path.dirname(__file__))

# Delegate to golden_runner verification
from golden_runner import verify_golden_snapshot

if __name__ == "__main__":
    success = verify_golden_snapshot()
    sys.exit(0 if success else 1)
