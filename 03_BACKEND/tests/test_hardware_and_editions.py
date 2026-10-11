"""
03_BACKEND/tests/test_hardware_and_editions.py
Tests for hardware profiling, edition recommendations (Lite / Standard / Pro / Server),
and the single shared resident local model invariant.
"""
from hopzero.core.hardware import (
    detect_hardware,
    HardwareProfile,
    get_or_create_hardware_profile,
)
from app.config import get_settings


def test_detect_hardware_returns_valid_profile():
    profile = detect_hardware()
    assert isinstance(profile, HardwareProfile)
    assert profile.cpu_cores >= 1
    assert profile.ram_gb > 0.0
    assert profile.recommended_edition in ("Lite", "Standard", "Pro", "Server")
    assert profile.recommendation_reason


def test_single_shared_local_model_invariant():
    profile = detect_hardware()
    settings = get_settings()

    # Invariant: Both HopZero core and bot tools share the single resident hermes3:3b model
    assert profile.recommended_settings["shared_model"] == "hermes3:3b"
    assert profile.recommended_settings["shared_model"] == settings.hopzero_llm_model
    assert "a8851c" in profile.recommended_settings["shared_model_digest"]
    assert profile.recommended_settings["shared_model_quantization"] == "Q4_K_M"
    assert profile.recommended_settings["shared_context_window"] == 4096


def test_edition_endpoint_returns_ok(client):
    res = client.get("/api/v1/system/edition")
    assert res.status_code == 200
    data = res.json()
    assert "cpu_cores" in data
    assert "ram_gb" in data
    assert "recommended_edition" in data
    assert data["recommended_edition"] in ("Lite", "Standard", "Pro", "Server")
    assert data["recommended_settings"]["shared_model"] == "hermes3:3b"
