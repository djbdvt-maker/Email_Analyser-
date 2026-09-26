"""
SUPERSEDED in V4.

Earlier architecture guidance treated the Score Engine as an external
component the backend merely called through a contract interface. The
V4 corrections doc explicitly supersedes that: the backend now OWNS
the deterministic Score Engine directly. See
app/services/score_engine.py, app/services/floor_engine.py, and
app/services/score_engine_service.py for the real implementation.

This file is kept only as a pointer so nothing silently imports a
stale interface; it intentionally exposes nothing.
"""
