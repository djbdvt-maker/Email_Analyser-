"""
hopzero.core.clock
Timezone-aware UTC time provider with injectable clock support for deterministic testing.
Ensures zero naive datetimes across all forensic calculations and analysis timestamps.
"""
from datetime import datetime, timezone
from typing import Optional
from contextlib import contextmanager

_OVERRIDE_CLOCK: Optional[datetime] = None


def get_utc_now() -> datetime:
    """
    Returns the current timezone-aware UTC datetime.
    If a clock override is active (e.g. during replay or tests), returns the frozen time.
    """
    global _OVERRIDE_CLOCK
    if _OVERRIDE_CLOCK is not None:
        if _OVERRIDE_CLOCK.tzinfo is None:
            return _OVERRIDE_CLOCK.replace(tzinfo=timezone.utc)
        return _OVERRIDE_CLOCK.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def get_utc_iso() -> str:
    """Returns ISO-8601 formatted UTC string with 'Z' suffix."""
    return get_utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


def set_clock_override(dt: Optional[datetime]) -> None:
    """Sets a global clock override for deterministic tests."""
    global _OVERRIDE_CLOCK
    if dt is not None and dt.tzinfo is None:
        _OVERRIDE_CLOCK = dt.replace(tzinfo=timezone.utc)
    else:
        _OVERRIDE_CLOCK = dt


def reset_clock_override() -> None:
    """Clears any clock override, returning to live wall-clock time."""
    global _OVERRIDE_CLOCK
    _OVERRIDE_CLOCK = None


@contextmanager
def frozen_clock(dt: datetime):
    """Context manager for temporarily overriding current time."""
    prev = _OVERRIDE_CLOCK
    try:
        set_clock_override(dt)
        yield
    finally:
        set_clock_override(prev)
