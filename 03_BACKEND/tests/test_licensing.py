"""
Unit tests for Section 10: Business & Licensing Architecture (Ed25519).
Verifies offline asymmetric Ed25519 cryptographic license token generation,
tamper detection, expiration checks, fallback defaults, and API endpoints.
"""
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from app.main import app
from hopzero.core.licensing import (
    generate_license_key,
    verify_license_key,
    get_active_license,
    LicenseInfo,
)

client = TestClient(app)

TEST_PRIV_KEY = ed25519.Ed25519PrivateKey.generate()
TEST_PUB_BYTES = TEST_PRIV_KEY.public_key().public_bytes_raw()

WRONG_PRIV_KEY = ed25519.Ed25519PrivateKey.generate()
WRONG_PUB_BYTES = WRONG_PRIV_KEY.public_key().public_bytes_raw()


def test_license_key_generation_and_verification():
    expires_at = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    key = generate_license_key(
        customer_id="SOC-CYBER-LABS-99",
        edition="Pro",
        expires_at=expires_at,
        max_seats=15,
        features=["core_forensics", "gpu_acceleration", "botchain_studio_tools"],
        private_key=TEST_PRIV_KEY,
    )

    assert key.startswith("HZ-PRO-")
    info = verify_license_key(key, trusted_public_keys=[TEST_PUB_BYTES])

    assert info.is_valid is True
    assert info.edition == "Pro"
    assert info.customer_id == "SOC-CYBER-LABS-99"
    assert info.max_seats == 15
    assert info.is_expired is False
    assert "gpu_acceleration" in info.features
    assert info.error_message is None


def test_tampered_signature_rejected():
    expires_at = (datetime.now(timezone.utc) + timedelta(days=100)).isoformat()
    key = generate_license_key(
        customer_id="ORG-TEST",
        edition="Standard",
        expires_at=expires_at,
        private_key=TEST_PRIV_KEY,
    )

    # Tamper with signature
    parts = key.split("-")
    tampered_sig = parts[-1][:-4] + "AAAA"
    tampered_key = "-".join(parts[:-1] + [tampered_sig])

    info = verify_license_key(tampered_key, trusted_public_keys=[TEST_PUB_BYTES])
    assert info.is_valid is False
    assert "signature verification failed" in info.error_message.lower()


def test_tampered_payload_edition_mismatch():
    expires_at = (datetime.now(timezone.utc) + timedelta(days=100)).isoformat()
    key = generate_license_key(
        customer_id="ORG-TEST",
        edition="Standard",
        expires_at=expires_at,
        private_key=TEST_PRIV_KEY,
    )

    # Change header edition from STANDARD to PRO
    parts = key.split("-")
    parts[1] = "PRO"
    tampered_key = "-".join(parts)

    info = verify_license_key(tampered_key, trusted_public_keys=[TEST_PUB_BYTES])
    assert info.is_valid is False


def test_wrong_key_rejected():
    expires_at = (datetime.now(timezone.utc) + timedelta(days=100)).isoformat()
    key = generate_license_key(
        customer_id="ORG-TEST",
        edition="Standard",
        expires_at=expires_at,
        private_key=WRONG_PRIV_KEY,
    )

    info = verify_license_key(key, trusted_public_keys=[TEST_PUB_BYTES])
    assert info.is_valid is False
    assert "signature verification failed" in info.error_message.lower()


def test_expired_license_key_detected():
    past_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    key = generate_license_key(
        customer_id="ORG-EXPIRED",
        edition="Lite",
        expires_at=past_date,
        private_key=TEST_PRIV_KEY,
    )

    info = verify_license_key(key, trusted_public_keys=[TEST_PUB_BYTES])
    assert info.is_valid is False
    assert info.is_expired is True
    assert "expired" in info.error_message.lower()


def test_malformed_license_key_rejected():
    bad_keys = [
        "",
        "NOT_A_KEY",
        "HZ-INVALID",
        "HZ-PRO-only-three-parts",
        "HZ-PRO-invalidb64payload-invalidsig",
    ]
    for bk in bad_keys:
        info = verify_license_key(bk, trusted_public_keys=[TEST_PUB_BYTES])
        assert info.is_valid is False


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
