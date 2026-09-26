"""
Infrastructure Reputation Dataset v1 (Curated, Versioned, Static)

Used by Infrastructure analyzer for known bad ASNs and bulletproof hosting.
"""
from dataclasses import dataclass
from typing import Tuple, Dict

INFRASTRUCTURE_REPUTATION_VERSION = "infra_rep_v1"

@dataclass(frozen=True)
class KnownBadASN:
    asn: int
    name: str
    threat_category: str

@dataclass(frozen=True)
class BulletproofProvider:
    provider_id: str
    name: str
    ip_prefixes: Tuple[str, ...]

KNOWN_BAD_ASNS: Dict[int, KnownBadASN] = {
    65501: KnownBadASN(asn=65501, name="Malicious-Relay-Network", threat_category="bulletproof_hosting"),
    65502: KnownBadASN(asn=65502, name="SpamMTA-Hosting", threat_category="known_phishing_origin"),
}

BULLETPROOF_PREFIXES: Tuple[str, ...] = (
    "198.51.100.128/25",
    "203.0.113.64/26",
    "192.0.2.100",
)

OFFLINE_MALICIOUS_URL_HASHES: Tuple[str, ...] = (
    # Pre-hashed known malicious links (SHA-256)
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
)