"""
HopZero Domain & Lookalike Checker - Core Service.
==================================================
Deterministic, offline-capable domain analysis engine:
- Punycode & IDN detection
- Mixed-script detection
- Homoglyph & confusable matching
- Protected brand lookalike & typosquatting detection
- Zero LLM scoring authority
"""
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from hopzero.core.models import NormalizedEntity
from hopzero_forensics.config.protected_brands_v1 import (
    PROTECTED_BRANDS,
    PROTECTED_BRANDS_VERSION,
    ProtectedBrand,
)

HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
    '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u03bf': 'o',
    '\u03c1': 'p', '0': 'o', '1': 'l', '3': 'e', '5': 's',
}

_DOMAIN_CLEAN_REGEX = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")


def normalize_domain_string(raw_domain: str) -> str:
    """Normalizes a raw domain string by stripping protocols, ports, and casing."""
    cleaned = (raw_domain or "").strip().lower()
    if "://" in cleaned:
        cleaned = cleaned.split("://")[-1]
    if "/" in cleaned:
        cleaned = cleaned.split("/")[0]
    if ":" in cleaned:
        cleaned = cleaned.split(":")[0]
    return cleaned.rstrip(".")


def check_punycode(domain: str) -> bool:
    """Checks whether the domain uses Punycode encoding."""
    return "xn--" in domain.lower()


def check_mixed_script(domain: str) -> bool:
    """Checks whether the domain mixes different Unicode scripts (e.g. Latin + Cyrillic)."""
    scripts = set()
    for ch in domain:
        if ch.isalnum():
            name = unicodedata.name(ch, "")
            if "LATIN" in name:
                scripts.add("LATIN")
            elif "CYRILLIC" in name:
                scripts.add("CYRILLIC")
            elif "GREEK" in name:
                scripts.add("GREEK")
            elif "ARABIC" in name:
                scripts.add("ARABIC")
    return len(scripts) > 1


def check_brand_lookalike(domain: str) -> Tuple[bool, bool, Optional[str], Optional[str]]:
    """
    Checks if domain is a lookalike or homoglyph of a protected brand.
    Returns: (is_lookalike, is_homoglyph, brand_canonical_name, detail)
    """
    clean = normalize_domain_string(domain)
    for brand_id, brand in PROTECTED_BRANDS.items():
        # Legitimate domain or official subdomain -> clean
        if clean in brand.protected_domains or clean in brand.legitimate_alternates:
            return False, False, None, None
        for legit in brand.protected_domains + brand.legitimate_alternates:
            if clean.endswith("." + legit):
                return False, False, None, None

        for p_dom in brand.protected_domains:
            root = p_dom.split(".")[0]
            # 1. Homoglyph confusable check
            folded = "".join(HOMOGLYPH_MAP.get(c, c) for c in clean)
            if folded != clean and (root in folded or p_dom in folded):
                return True, True, brand.canonical_name, f"Homoglyph confusable spoofing '{brand.canonical_name}' ({root}): {clean}"

            # 2. Lookalike / typosquatting check on SLD
            parts = clean.split(".")
            sld = parts[-2] if len(parts) >= 2 else parts[0]
            if len(root) >= 4 and (
                sld.startswith(f"{root}-")
                or sld.endswith(f"-{root}")
                or f"-{root}-" in sld
                or sld.startswith(f"{root}security")
                or sld.startswith(f"{root}update")
                or sld.startswith(f"{root}support")
                or sld.startswith(f"{root}login")
                or sld.startswith(f"{root}verify")
                or sld.startswith(f"{root}account")
                or sld.startswith(f"{root}id")
                or sld.endswith(f"security-{root}")
                or sld.endswith(f"update-{root}")
                or (root in sld and any(kw in sld for kw in ("security", "update", "support", "login", "verify", "account", "id", "alert", "center")))
            ):
                return True, False, brand.canonical_name, f"Lookalike domain spoofing '{brand.canonical_name}' ({p_dom}): {clean}"

    return False, False, None, None


@dataclass
class DomainCheckResult:
    domain: str
    normalized_domain: str
    is_lookalike: bool
    is_homoglyph: bool
    is_punycode: bool
    is_mixed_script: bool
    matched_brand: Optional[str]
    risk_verdict: str  # LOW, MEDIUM, HIGH, CRITICAL
    facts: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    entity: Optional[NormalizedEntity] = None
    untrusted_fields: Dict[str, str] = field(default_factory=dict)


def analyze_domain(domain_input: str, context: Optional[Dict[str, Any]] = None) -> DomainCheckResult:
    """Analyzes a single domain deterministically."""
    clean = normalize_domain_string(domain_input)
    punycode = check_punycode(clean)
    mixed_script = check_mixed_script(clean)
    lookalike, homoglyph, brand, detail = check_brand_lookalike(clean)

    facts = [
        {"key": "normalized_domain", "value": clean, "category": "Domain"},
        {"key": "is_punycode", "value": str(punycode), "category": "Domain"},
        {"key": "is_mixed_script", "value": str(mixed_script), "category": "Domain"},
        {"key": "is_lookalike", "value": str(lookalike), "category": "Domain"},
        {"key": "is_homoglyph", "value": str(homoglyph), "category": "Domain"},
    ]
    if brand:
        facts.append({"key": "matched_brand", "value": brand, "category": "Domain", "detail": detail})

    findings = []
    if homoglyph:
        findings.append({
            "category": "Domain",
            "qualification_code": "HOMOGLYPH_DOMAIN",
            "strength": "Strong",
            "normalized_subject": clean,
            "normalized_target": brand,
            "detail": detail,
        })
    elif lookalike:
        findings.append({
            "category": "Domain",
            "qualification_code": "LOOKALIKE_BRAND_DOMAIN",
            "strength": "Strong",
            "normalized_subject": clean,
            "normalized_target": brand,
            "detail": detail,
        })

    if punycode and not homoglyph:
        findings.append({
            "category": "Domain",
            "qualification_code": "PUNYCODE_DOMAIN_OBSERVED",
            "strength": "Moderate",
            "normalized_subject": clean,
            "detail": f"Domain {clean} uses punycode IDN encoding",
        })

    # Deterministic verdict logic
    if homoglyph:
        verdict = "CRITICAL"
    elif lookalike:
        verdict = "HIGH"
    elif punycode or mixed_script:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    entity = NormalizedEntity(
        entity_type="domain",
        normalized_value=clean,
        raw_value=domain_input,
        provenance=context or {},
    )

    return DomainCheckResult(
        domain=domain_input,
        normalized_domain=clean,
        is_lookalike=lookalike,
        is_homoglyph=homoglyph,
        is_punycode=punycode,
        is_mixed_script=mixed_script,
        matched_brand=brand,
        risk_verdict=verdict,
        facts=facts,
        findings=findings,
        entity=entity,
        untrusted_fields={"input_domain": domain_input},
    )


def analyze_domains_batch(domains: List[str]) -> List[DomainCheckResult]:
    """Analyzes a list of domains."""
    return [analyze_domain(d) for d in domains[:100]]
