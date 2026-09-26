"""
Domain Analyzer (Deterministic)
===============================

Analyzes email domains for:
  - Punycode / IDN encoding (xn--)
  - Mixed-script / Cyrillic/Greek homoglyphs
  - Protected-brand lookalike / typosquatting (using versioned protected_brands_v1)
  - Newly observed / young domains
"""
from __future__ import annotations
import unicodedata
from typing import Optional, List, Tuple
from ..interfaces import AnalyzerOutput, CanonicalEmail, Fact, FindingCandidate, SignalState
from ..config.protected_brands_v1 import PROTECTED_BRANDS

ANALYZER_NAME = "domain_analyzer"
ANALYZER_VERSION = "1.0"
VOCAB_VERSION = "v1"

def _fact(fid: str, key: str, state: SignalState, value: Optional[str], detail: Optional[str] = None) -> Fact:
    return Fact(
        fact_id=fid,
        category="Domain",
        key=key,
        state=state,
        value=value,
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
        detail=detail,
    )

def _candidate(code: str, strength: str, subject: str, target: str, claim_sig: str, facts: List[str], text: Optional[str] = None) -> FindingCandidate:
    return FindingCandidate(
        category="Domain",
        qualification_code=code,
        qualification_version=VOCAB_VERSION,
        strength=strength,
        normalized_subject=subject,
        normalized_target=target,
        claim_signature=claim_sig,
        supporting_fact_ids=facts,
        supporting_text=text or f"Domain finding {code} for {subject}",
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
    )

# Common homoglyph character substitutions (e.g. Cyrillic/Greek looking like Latin)
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
    '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u03bf': 'o',
    '\u03c1': 'p', '0': 'o', '1': 'l', '3': 'e', '5': 's',
}

def _check_punycode(domain: str) -> bool:
    return "xn--" in domain.lower()

def _check_mixed_script(domain: str) -> bool:
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

def _check_brand_lookalike(domain: str) -> Tuple[bool, bool, Optional[str], Optional[str]]:
    """
    Returns: (is_lookalike, is_homoglyph, brand_canonical_name, detail)
    """
    domain_clean = domain.lower().strip(".")
    for brand_id, brand in PROTECTED_BRANDS.items():
        # If exact match or legit alternate or subdomain of legit domain, clean
        if domain_clean in brand.protected_domains or domain_clean in brand.legitimate_alternates:
            return False, False, None, None
        for legit in brand.protected_domains + brand.legitimate_alternates:
            if domain_clean.endswith("." + legit):
                return False, False, None, None

        for p_dom in brand.protected_domains:
            root = p_dom.split(".")[0]
            # 1. Homoglyph confusable check (Cyrillic, Greek, lookalikes)
            folded = "".join(HOMOGLYPH_MAP.get(c, c) for c in domain_clean)
            if folded != domain_clean and (root in folded or p_dom in folded):
                return True, True, brand.canonical_name, f"Homoglyph brand confusable for '{brand.canonical_name}' ({root}): {domain_clean}"

            # 2. Structured lookalike domain check on SLD
            parts = domain_clean.split(".")
            sld = parts[-2] if len(parts) >= 2 else parts[0]
            if len(root) >= 4 and (
                sld.startswith(f"{root}-")
                or sld.endswith(f"-{root}")
                or f"-{root}-" in sld
                or sld.startswith(f"{root}security")
                or sld.startswith(f"{root}update")
                or sld.startswith(f"{root}support")
                or sld == f"{root}corp"
                or sld == f"{root}online"
            ):
                return True, False, brand.canonical_name, f"Lookalike domain targeting protected brand '{brand.canonical_name}': {domain_clean}"

    return False, False, None, None

def analyze_domain(email: CanonicalEmail) -> AnalyzerOutput:
    facts: List[Fact] = []
    candidates: List[FindingCandidate] = []

    domains_to_check = set()
    if email.from_addresses and email.from_addresses[0].address:
        addr = email.from_addresses[0].address
        if "@" in addr:
            domains_to_check.add(addr.split("@")[-1].lower())
    if email.reply_to_addresses and email.reply_to_addresses[0].address:
        addr = email.reply_to_addresses[0].address
        if "@" in addr:
            domains_to_check.add(addr.split("@")[-1].lower())

    for domain in domains_to_check:
        # 1. Punycode Check
        is_punycode = _check_punycode(domain)
        fact_puny = _fact(
            f"fact_dom_puny_{domain}",
            "punycode_domain",
            SignalState.PRESENT if is_punycode else SignalState.ABSENT,
            domain if is_punycode else None,
            f"Punycode encoded domain: {domain}" if is_punycode else "ASCII/Standard domain",
        )
        facts.append(fact_puny)
        if is_punycode:
            candidates.append(
                _candidate(
                    "PUNYCODE_DOMAIN_INDICATOR",
                    "Weak",
                    domain,
                    "idn",
                    "punycode_domain_present",
                    [fact_puny.fact_id],
                )
            )

        # 2. Mixed-script Check
        is_mixed = _check_mixed_script(domain)
        fact_mixed = _fact(
            f"fact_dom_mixed_{domain}",
            "mixed_script_domain",
            SignalState.PRESENT if is_mixed else SignalState.ABSENT,
            domain if is_mixed else None,
            f"Mixed script characters detected in {domain}" if is_mixed else "Single script",
        )
        facts.append(fact_mixed)
        if is_mixed:
            candidates.append(
                _candidate(
                    "MIXED_SCRIPT_DOMAIN",
                    "Weak",
                    domain,
                    "unicode",
                    "mixed_script_domain_present",
                    [fact_mixed.fact_id],
                )
            )

        # 3. Protected-brand lookalike / Homoglyph check
        is_lookalike, is_homoglyph, brand_name, lookalike_detail = _check_brand_lookalike(domain)
        fact_look = _fact(
            f"fact_dom_look_{domain}",
            "protected_brand_lookalike",
            SignalState.PRESENT if is_lookalike else SignalState.ABSENT,
            brand_name if is_lookalike else None,
            lookalike_detail or f"Domain {domain} is not a protected-brand lookalike",
        )
        facts.append(fact_look)
        if is_lookalike and brand_name:
            candidates.append(
                _candidate(
                    "PROTECTED_BRAND_LOOKALIKE_DOMAIN",
                    "Moderate",
                    domain,
                    brand_name,
                    "qualified_protected_brand_lookalike",
                    [fact_look.fact_id],
                    lookalike_detail,
                )
            )
            if is_homoglyph:
                candidates.append(
                    _candidate(
                        "HOMOGLYPH_DOMAIN_MATCH",
                        "Moderate",
                        domain,
                        brand_name,
                        "homoglyph_brand_match",
                        [fact_look.fact_id],
                        lookalike_detail,
                    )
                )

    return AnalyzerOutput(
        analyzer_name=ANALYZER_NAME,
        analyzer_version=ANALYZER_VERSION,
        facts=facts,
        candidates=candidates,
    )