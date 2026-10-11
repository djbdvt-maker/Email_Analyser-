"""
Unit tests for Section 10: Business & Licensing Architecture.
Verifies offline cryptographic license token generation, tamper detection,
expiration checks, fallback defaults, and API endpoints.
"""
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from app.main import app
from hopzero.core.licensing import (
    generate_license_key,
    verify_license_key,
    get_active_license,
    LicenseInfo,
)

client = TestClient(app)


def test_license_key_generation_and_verification():
    expires_at = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    key = generate_license_key(
        customer_id="SOC-CYBER-LABS-99",
        edition="Pro",
        expires_at=expires_at,
        max_seats=15,
        features=["core_forensics", "gpu_acceleration", "botchain_studio_tools"],
    )

    assert key.startswith("HZ-PRO-")
    info = verify_license_key(key)

    assert info.is_valid is True
    assert info.edition == "Pro"
    assert info.customer_id == "SOC-CYBER-LABS-99"
    assert info.max_seats == 15
    assert info.is_expired is False
    assert "gpu_acceleration" in info.features
    assert info.error_message is None


def test_tampered_license_key_rejected():
    expires_at = (datetime.now(timezone.utc) + timedelta(days=100)).isoformat()
    key = generate_license_key(customer_id="ORG-TEST", edition="Standard", expires_at=expires_at)

    # Tamper with signature
    parts = key.split("-")
    tampered_sig = parts[-1][:-4] + "0000"
    tampered_key = "-".join(parts[:-1] + [tampered_sig])

    info = verify_license_key(tampered_key)
    assert info.is_valid is False
    assert "signature verification failed" in info.error_message.lower()


def test_expired_license_key_detected():
    past_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    key = generate_license_key(customer_id="ORG-EXPIRED", edition="Lite", expires_at=past_date)

    info = verify_license_key(key)
    assert info.is_valid is False
    assert info.is_expired is True
    assert "expired" in info.error_message.lower()


def test_default_community_license_fallback():
    info = get_active_license()
    assert info.is_valid is True
    assert info.edition == "Community"
    assert "core_forensics" in info.features
    assert "deterministic_scoring" in info.features


def test_api_system_license_endpoint():
    res = client.get("/api/v1/system/license")
    assert res.status_code == 200
    data = res.json()
    assert "is_valid" in data
    assert "edition" in data
    assert "features" in data
    assert data["is_valid"] is True
