"""
03_BACKEND/app/api/v1/routes_system.py
System diagnostics, hardware profiling, and edition recommendation API endpoints.
"""
from fastapi import APIRouter
from hopzero.core.hardware import get_or_create_hardware_profile
from scripts.doctor import run_diagnostics

router = APIRouter(prefix="/system", tags=["System & Editions"])


@router.get("/edition", summary="Get system hardware profile and edition recommendation")
def get_system_edition():
    """
    Returns the auto-detected system hardware specs (RAM, CPU, GPU, VRAM)
    and the recommended edition (Lite, Standard, Pro, Server), confirming
    the single shared local model settings across HopZero and bot tools.
    """
    profile = get_or_create_hardware_profile()
    return profile.to_dict()


@router.get("/doctor", summary="Run system diagnostics")
def get_system_doctor():
    """Returns real-time doctor diagnostics across versions, ports, disk, and models."""
    checks = run_diagnostics(verbose=False)
    all_ok = all(c.passed for c in checks)
    return {
        "status": "ok" if all_ok else "warning_or_failed",
        "all_passed": all_ok,
        "checks": [
            {
                "name": c.name,
                "passed": c.passed,
                "warning": c.warning,
                "message": c.message,
                "fix_hint": c.fix_hint,
            }
            for c in checks
        ]
    }
