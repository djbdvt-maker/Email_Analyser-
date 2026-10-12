"""
hopzero.core.licensing
Offline-verifiable commercial license key verification and edition entitlement module.
Guarantees 100% air-gapped cryptographic validation using asymmetric Ed25519 digital signatures.
The application contains only trusted public keys; the private signing key stays strictly offline.
"""
import base64
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from hopzero.core.paths import get_app_data_root

# Master official Ed25519 public keys embedded in application for offline verification
OFFICIAL_LICENSE_PUBLIC_KEYS = [
    # Primary Master Licensing Authority Public Key (v1)
    bytes.fromhex("b57f9cbcd7b4e6379f52c4548e91b40a2ef4ada5b016261ab332e999c7b0ee38"),
]

VALID_EDITIONS = {"Community", "Lite", "Standard", "Pro", "Server"}


def get_trusted_public_keys() -> List[bytes]:
    """Returns the list of trusted Ed25519 public keys for license verification."""
    keys = list(OFFICIAL_LICENSE_PUBLIC_KEYS)
    custom_keys_env = os.getenv("HOPZERO_TRUSTED_LICENSE_PUBLIC_KEYS")
    if custom_keys_env:
        for k in custom_keys_env.split(","):
            k = k.strip()
            if k:
                try:
                    raw = bytes.fromhex(k) if len(k) == 64 else base64.urlsafe_b64decode(k + "=" * (-len(k) % 4))
                    if len(raw) == 32:
                        keys.append(raw)
                except Exception:
                    pass
    return keys


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


def _coerce_private_key(key: Union[ed25519.Ed25519PrivateKey, bytes, str]) -> ed25519.Ed25519PrivateKey:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return key
    if isinstance(key, str):
        key = key.strip()
        raw = bytes.fromhex(key) if len(key) == 64 else base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
    if isinstance(key, (bytes, bytearray)):
        return ed25519.Ed25519PrivateKey.from_private_bytes(bytes(key))
    raise TypeError(f"Unsupported private key type: {type(key)}")


def generate_license_key(
    customer_id: str,
    edition: str,
    expires_at: str,
    max_seats: int = 5,
    features: Optional[List[str]] = None,
    private_key: Optional[Union[ed25519.Ed25519PrivateKey, bytes, str]] = None,
    issued_at: Optional[str] = None,
) -> str:
    """
    Generates an Ed25519 cryptographically signed offline commercial license token.
    Format: HZ-<EDITION>-<BASE64_PAYLOAD>-<BASE64_SIGNATURE>
    Requires maintainer offline Ed25519 private key.
    """
    if private_key is None:
        env_priv = os.getenv("HOPZERO_LICENSE_PRIVATE_KEY")
        if env_priv:
            private_key = env_priv
        else:
            raise ValueError(
                "An Ed25519 private key is required to sign commercial license tokens. "
                "Maintainers should use 'tools/sign_license.py' or supply private_key."
            )

    signing_key = _coerce_private_key(private_key)

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
        "v": 1,
        "customer_id": customer_id,
        "edition": edition,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "max_seats": int(max_seats),
        "features": list(features),
    }

    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode("ascii").rstrip("=")

    # Ed25519 sign canonical edition:payload_b64
    sign_target = f"{edition.upper()}:{payload_b64}".encode("utf-8")
    sig_bytes = signing_key.sign(sign_target)
    sig_hex = sig_bytes.hex()

    return f"HZ-{edition.upper()}-{payload_b64}-{sig_hex}"


def verify_license_key(
    key_string: str,
    trusted_public_keys: Optional[List[bytes]] = None,
    now: Optional[datetime] = None,
) -> LicenseInfo:
    """
    Cryptographically verifies an offline license key string using Ed25519 public key verification.
    Checks digital signature, edition matching, and expiration date.
    Never initiates network requests.
    """
    if not key_string or not isinstance(key_string, str):
        return LicenseInfo(
            is_valid=False,
            edition="Community",
            customer_id="unlicensed",
            error_message="License key string is empty or invalid",
        )

    parts = key_string.strip().split("-")
    if len(parts) < 4 or parts[0] != "HZ":
        return LicenseInfo(
            is_valid=False,
            edition="Community",
            customer_id="unlicensed",
            error_message="Malformed license key format. Expected HZ-<EDITION>-<PAYLOAD>-<SIG>",
        )

    edition_hdr = parts[1]
    sig_hex = parts[-1]
    payload_b64 = "-".join(parts[2:-1])

    # 1. Decode payload and signature
    try:
        pad_payload = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(pad_payload.encode("ascii"))
        data = json.loads(payload_bytes.decode("utf-8"))

        if len(sig_hex) == 128:
            sig_bytes = bytes.fromhex(sig_hex)
        else:
            pad_sig = sig_hex + "=" * (-len(sig_hex) % 4)
            sig_bytes = base64.urlsafe_b64decode(pad_sig.encode("ascii"))
    except Exception as e:
        return LicenseInfo(
            is_valid=False,
            edition="Community",
            customer_id="unlicensed",
            error_message=f"Failed to decode license token: {str(e)}",
        )

    edition = data.get("edition", "Community")
    customer_id = data.get("customer_id", "unknown")
    issued_at = data.get("issued_at")
    expires_at = data.get("expires_at")
    max_seats = data.get("max_seats", 1)
    features = data.get("features", [])

    if edition.upper() != edition_hdr.upper():
        return LicenseInfo(
            is_valid=False,
            edition=edition,
            customer_id=customer_id,
            error_message="Edition mismatch between token header and signed payload",
        )

    # 2. Verify Ed25519 signature
    sign_target = f"{edition_hdr.upper()}:{payload_b64}".encode("utf-8")
    keys_to_try = trusted_public_keys or get_trusted_public_keys()
    signature_verified = False

    for pub_raw in keys_to_try:
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
            pub_key.verify(sig_bytes, sign_target)
            signature_verified = True
            break
        except (InvalidSignature, ValueError):
            continue

    if not signature_verified:
        return LicenseInfo(
            is_valid=False,
            edition=edition,
            customer_id=customer_id,
            error_message="Cryptographic signature verification failed (invalid or tampered key)",
        )

    # 3. Check expiration
    is_expired = False
    if expires_at:
        try:
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
