"""
Links Analyzer (Static Only)
============================

Performs static analysis on extracted links:
  - Text vs href mismatch (anchor says Brand X, href goes to unrelated target)
  - Known URL shorteners
  - Auth-like paths (/login, /verify, /signin) on non-authoritative domains
  - Protected-brand lookalikes in URL hostnames
  - Exact local malicious blocklist match

NO live fetching, NO browser rendering, NO redirect following.
"""
from __future__ import annotations
import urllib.parse
import hashlib
from typing import Optional, List
from ..interfaces import AnalyzerOutput, CanonicalEmail, Fact, FindingCandidate, SignalState
from ..config.protected_brands_v1 import PROTECTED_BRANDS
from ..config.infrastructure_reputation_v1 import OFFLINE_MALICIOUS_URL_HASHES
from .domain import _check_brand_lookalike

ANALYZER_NAME = "links_analyzer"
ANALYZER_VERSION = "1.0"
VOCAB_VERSION = "v1"

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "goo.gl", "shorte.st", "cutt.ly",
}

AUTH_PATHS = ("/login", "/signin", "/verify", "/auth", "/security", "/update-account", "/password-reset")

def _fact(fid: str, key: str, state: SignalState, value: Optional[str], detail: Optional[str] = None) -> Fact:
    return Fact(
        fact_id=fid,
        category="Links",
        key=key,
        state=state,
        value=value,
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
        detail=detail,
    )

def _candidate(code: str, strength: str, subject: str, target: str, claim_sig: str, facts: List[str], text: Optional[str] = None) -> FindingCandidate:
    return FindingCandidate(
        category="Links",
        qualification_code=code,
        qualification_version=VOCAB_VERSION,
        strength=strength,
        normalized_subject=subject,
        normalized_target=target,
        claim_signature=claim_sig,
        supporting_fact_ids=facts,
        supporting_text=text or f"Link security finding {code} on {subject}",
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
    )

def analyze_links(email: CanonicalEmail) -> AnalyzerOutput:
    facts: List[Fact] = []
    candidates: List[FindingCandidate] = []

    links = email.body.links or []

    for i, link in enumerate(links):
        href = link.href or ""
        display = (link.display_text or "").strip()
        parsed = urllib.parse.urlparse(href)
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()

        # 1. Offline blocklist exact match (SHA-256 hash match)
        url_hash = hashlib.sha256(href.encode("utf-8")).hexdigest()
        if url_hash in OFFLINE_MALICIOUS_URL_HASHES:
            fact_bl = _fact(f"fact_link_bl_{i}", "offline_blocklist_match", SignalState.PRESENT, href, f"URL matches local malicious indicator database")
            facts.append(fact_bl)
            candidates.append(
                _candidate(
                    "CONFIRMED_MALICIOUS_INDICATOR",
                    "Strong",
                    netloc or href,
                    "malicious_blocklist",
                    "exact_confirmed_malicious_indicator",
                    [fact_bl.fact_id],
                    f"Confirmed malicious indicator match on {href}",
                )
            )

        # 2. Visible text vs href mismatch
        if display and ("http://" in display.lower() or "https://" in display.lower() or "." in display):
            disp_parsed = urllib.parse.urlparse(display if "://" in display else f"http://{display}")
            disp_netloc = disp_parsed.netloc.lower()
            if disp_netloc and netloc and disp_netloc != netloc:
                detail = f"Anchor text displays '{display}' but target points to '{href}'"
                fact_mis = _fact(f"fact_link_mis_{i}", "anchor_href_mismatch", SignalState.PRESENT, href, detail)
                facts.append(fact_mis)
                candidates.append(
                    _candidate(
                        "LINK_DISPLAY_HREF_MISMATCH",
                        "Weak",
                        href,
                        disp_netloc,
                        "visible_text_href_mismatch",
                        [fact_mis.fact_id],
                        detail,
                    )
                )

        # 3. URL shorteners
        if netloc in URL_SHORTENERS:
            detail = f"Link uses known URL shortener service: {netloc}"
            fact_short = _fact(f"fact_link_short_{i}", "url_shortener", SignalState.PRESENT, netloc, detail)
            facts.append(fact_short)
            candidates.append(
                _candidate(
                    "URL_SHORTENER_DETECTED",
                    "Weak",
                    href,
                    netloc,
                    "known_url_shortener",
                    [fact_short.fact_id],
                    detail,
                )
            )

        # 4. Protected-brand lookalike URL (using shared protected-brand algorithm)
        is_brand_lookalike, is_homoglyph, brand_name, lookalike_detail = _check_brand_lookalike(netloc)
        if (is_brand_lookalike or is_homoglyph) and brand_name:
            detail = lookalike_detail or f"Link domain '{netloc}' mimics protected brand '{brand_name}'"
            fact_brand = _fact(f"fact_link_brand_{i}", "protected_brand_lookalike_url", SignalState.PRESENT, netloc, detail)
            facts.append(fact_brand)
            candidates.append(
                _candidate(
                    "PROTECTED_BRAND_LOOKALIKE_URL",
                    "Moderate",
                    netloc,
                    brand_name,
                    "brand_lookalike_in_url",
                    [fact_brand.fact_id],
                    detail,
                )
            )

        # 5. Auth-like path on unrelated domain
        has_display_mismatch = (
            display and ("http://" in display.lower() or "https://" in display.lower() or "." in display)
            and disp_netloc and netloc and disp_netloc != netloc
        )
        for ap in AUTH_PATHS:
            if ap in path:
                # Check if netloc is a legitimate domain for major brands
                is_major_brand = any(
                    netloc == b_dom or netloc.endswith("." + b_dom) or netloc in b.legitimate_alternates
                    for b in PROTECTED_BRANDS.values() for b_dom in b.protected_domains
                )
                if not is_major_brand and netloc:
                    detail = f"Sensitive authentication-like path '{path}' hosted on unverified domain '{netloc}'"
                    fact_auth = _fact(f"fact_link_auth_{i}", "auth_path_detected", SignalState.PRESENT, href, detail)
                    facts.append(fact_auth)
                    candidates.append(
                        _candidate(
                            "AUTH_LIKE_PATH_DETECTED",
                            "Moderate",
                            netloc,
                            path,
                            "auth_path_on_unrelated_domain",
                            [fact_auth.fact_id],
                            detail,
                        )
                    )
                    # Definite CREDENTIAL_PHISHING_LINK requires deceptive intent:
                    # e.g. anchor text display-vs-href destination mismatch
                    if has_display_mismatch:
                        phish_detail = f"Credential phishing link: auth path '{path}' combined with deceptive anchor destination '{disp_netloc}' != '{netloc}'"
                        candidates.append(
                            _candidate(
                                "CREDENTIAL_PHISHING_LINK",
                                "Moderate",
                                netloc,
                                path,
                                "credential_harvesting_link",
                                [fact_auth.fact_id],
                                phish_detail,
                            )
                        )
                    break

    return AnalyzerOutput(
        analyzer_name=ANALYZER_NAME,
        analyzer_version=ANALYZER_VERSION,
        facts=facts,
        candidates=candidates,
    )