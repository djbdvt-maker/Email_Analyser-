"""
hopzero.core.licensing
Offline-verifiable commercial license key verification and edition entitlement module.
Guarantees 100% air-gapped cryptographic validation without external network calls.
"""
import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from hopzero.core.paths import get_app_data_root

DEFAULT_LICENSE_SECRET = "hopzero-commercial-master-licensing-authority-2026"

VALID_EDITIONS = {"Community", "Lite", "Standard", "Pro", "Server"}


@dataclass
class LicenseInfo:
    is_valid: bool
    edition: str
    customer_id: str
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None
    is_expired: bool = False
    max_seats: int = 1
    features: List[str] = field(default_factory=list)
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "is_valid": self.is_valid,
            "edition": self.edition,
            "customer_id": self.customer_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "is_expired": self.is_expired,
            "max_seats": self.max_seats,
            "features": self.features,
            "error_message": self.error_message,
        }


def generate_license_key(
    customer_id: str,
    edition: str,
    expires_at: str,
    max_seats: int = 5,
    features: Optional[List[str]] = None,
    secret_key: str = DEFAULT_LICENSE_SECRET,
    issued_at: Optional[str] = None,
) -> str:
    """
    Generates a cryptographically signed offline commercial license token.
    Format: HZ-<EDITION>-<BASE64_PAYLOAD>-<HMAC_SIGNATURE>
    """
    if edition not in VALID_EDITIONS:
        raise ValueError(f"Invalid edition '{edition}'. Must be one of {VALID_EDITIONS}")

    if issued_at is None:
        issued_at = datetime.now(timezone.utc).isoformat()

    if features is None:
        features = [
            "core_forensics",
            "offline_deterministic_scoring",
            "botchain_studio_tools",
            "section_63_evidence_pack",
        ]

    payload = {
        "customer_id": customer_id,
        "edition": edition,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "max_seats": max_seats,
        "features": features,
    }

    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode("ascii")

    # Compute HMAC signature over edition + payload
    sign_target = f"{edition}:{payload_b64}".encode("utf-8")
    sig = hmac.new(secret_key.encode("utf-8"), sign_target, hashlib.sha256).hexdigest()

    return f"HZ-{edition.upper()}-{payload_b64}-{sig}"


def verify_license_key(
    key_string: str,
    secret_key: str = DEFAULT_LICENSE_SECRET,
    now: Optional[datetime] = None,
) -> LicenseInfo:
    """
    Cryptographically verifies an offline license key string.
    Checks signature integrity, edition matching, and expiration date.
    Never initiates network requests.
    """
    if not key_string or not isinstance(key_string, str):
        return LicenseInfo(
            is_valid=False,
            edition="Community",
            customer_id="unlicensed",
            error_message="License key string is empty or invalid",
        )

    parts = key_string.strip().split("-", 3)
    if len(parts) != 4 or parts[0] != "HZ":
        return LicenseInfo(
            is_valid=False,
            edition="Community",
            customer_id="unlicensed",
            error_message="Malformed license key format. Expected HZ-<EDITION>-<PAYLOAD>-<SIG>",
        )

    _, edition_hdr, payload_b64, signature = parts

    # 1. Verify cryptographic signature
    sign_target = f"{edition_hdr.capitalize()}:{payload_b64}".encode("utf-8")
    expected_sig = hmac.new(secret_key.encode("utf-8"), sign_target, hashlib.sha256).hexdigest()

    # Also try exact header case
    sign_target_exact = f"{edition_hdr}:{payload_b64}".encode("utf-8")
    expected_sig_exact = hmac.new(secret_key.encode("utf-8"), sign_target_exact, hashlib.sha256).hexdigest()

    if not (hmac.compare_digest(expected_sig, signature) or hmac.compare_digest(expected_sig_exact, signature)):
        return LicenseInfo(
            is_valid=False,
            edition="Community",
            customer_id="unlicensed",
            error_message="Cryptographic signature verification failed (invalid or tampered key)",
        )

    # 2. Decode payload
    try:
        payload_json = base64.urlsafe_b64decode(payload_b64.encode("ascii")).decode("utf-8")
        data = json.loads(payload_json)
    except Exception as e:
        return LicenseInfo(
            is_valid=False,
            edition="Community",
            customer_id="unlicensed",
            error_message=f"Failed to decode license payload: {str(e)}",
        )

    edition = data.get("edition", "Community")
    customer_id = data.get("customer_id", "unknown")
    issued_at = data.get("issued_at")
    expires_at = data.get("expires_at")
    max_seats = data.get("max_seats", 1)
    features = data.get("features", [])

    # 3. Check expiration
    is_expired = False
    if expires_at:
        try:
            # Parse ISO date
            exp_clean = expires_at.replace("Z", "+00:00")
            exp_dt = datetime.fromisoformat(exp_clean)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)

            curr_dt = now or datetime.now(timezone.utc)
            if curr_dt > exp_dt:
                is_expired = True
                return LicenseInfo(
                    is_valid=False,
                    edition=edition,
                    customer_id=customer_id,
                    issued_at=issued_at,
                    expires_at=expires_at,
                    is_expired=True,
                    max_seats=max_seats,
                    features=features,
                    error_message=f"License expired on {expires_at}",
                )
        except Exception as e:
            return LicenseInfo(
                is_valid=False,
                edition=edition,
                customer_id=customer_id,
                error_message=f"Invalid expiration date format in license: {str(e)}",
            )

    return LicenseInfo(
        is_valid=True,
        edition=edition,
        customer_id=customer_id,
        issued_at=issued_at,
        expires_at=expires_at,
        is_expired=False,
        max_seats=max_seats,
        features=features,
    )


def get_active_license() -> LicenseInfo:
    """
    Resolves active license status for the running HopZero host:
    1. Checks HOPZERO_LICENSE_KEY environment variable.
    2. Checks %LOCALAPPDATA%/HopZero/license.key file.
    3. Defaults to free Community/Evaluation tier with core forensic features enabled.
    """
    # 1. Environment Variable
    env_key = os.getenv("HOPZERO_LICENSE_KEY")
    if env_key:
        result = verify_license_key(env_key)
        if result.is_valid:
            return result

    # 2. Filesystem key file
    key_file = get_app_data_root() / "license.key"
    if key_file.is_file():
        try:
            file_key = key_file.read_text(encoding="utf-8").strip()
            result = verify_license_key(file_key)
            if result.is_valid:
                return result
        except Exception:
            pass

    # 3. Default Community / Evaluation license (Core Forensics fully enabled)
    return LicenseInfo(
        is_valid=True,
        edition="Community",
        customer_id="community_evaluation",
        issued_at=None,
        expires_at=None,
        is_expired=False,
        max_seats=1,
        features=[
            "core_forensics",
            "deterministic_scoring",
            "sandbox_isolation",
            "progressive_disclosure_l1_l5",
            "section_63_evidence_pack",
            "botchain_studio_tools",
        ],
    )
