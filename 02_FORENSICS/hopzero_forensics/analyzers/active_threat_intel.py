"""
Active Threat Intel Analyzer
============================

Performs LIVE network requests to Threat Intelligence providers (like AbuseIPDB)
to check the reputation of domains extracted from the email.

Note: This analyzer requires outbound network access and an ABUSEIPDB_API_KEY
in your environment variables.
"""
from __future__ import annotations
import urllib.parse
import os
import requests
import socket
from typing import Optional, List
from ..interfaces import AnalyzerOutput, CanonicalEmail, Fact, FindingCandidate, SignalState

ANALYZER_NAME = "active_threat_intel"
ANALYZER_VERSION = "1.0"
VOCAB_VERSION = "v1"

def _fact(fid: str, key: str, state: SignalState, value: Optional[str], detail: Optional[str] = None) -> Fact:
    return Fact(
        fact_id=fid,
        category="ThreatIntel",
        key=key,
        state=state,
        value=value,
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
        detail=detail,
    )

def _candidate(code: str, strength: str, subject: str, target: str, claim_sig: str, facts: List[str], text: Optional[str] = None) -> FindingCandidate:
    return FindingCandidate(
        category="ThreatIntel",
        qualification_code=code,
        qualification_version=VOCAB_VERSION,
        strength=strength,
        normalized_subject=subject,
        normalized_target=target,
        claim_signature=claim_sig,
        supporting_fact_ids=facts,
        supporting_text=text or f"Threat Intel finding {code} on {subject}",
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
    )

def analyze_threat_intel(email: CanonicalEmail) -> AnalyzerOutput:
    facts: List[Fact] = []
    candidates: List[FindingCandidate] = []
    
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return AnalyzerOutput(
            analyzer_name=ANALYZER_NAME,
            analyzer_version=ANALYZER_VERSION,
            facts=facts,
            candidates=candidates
        )

    links = email.body.links or []
    checked_ips = set()
    
    # Known URL shorteners
    SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "goo.gl", "cutt.ly"}
    
    for i, link in enumerate(links):
        href = link.href or ""
        parsed = urllib.parse.urlparse(href)
        netloc = parsed.netloc.lower()
        if not netloc:
            continue
            
        # LIVE URL UNSHORTENING
        # If the domain is a known shortener, make a request to find where it redirects
        if netloc in SHORTENERS:
            try:
                # We use a 3-second timeout and don't allow redirects in the first request
                # just to read the Location header, or we can let requests resolve it.
                # Let's let requests resolve it up to 3 times to get the final destination.
                res = requests.head(href, allow_redirects=True, timeout=3)
                final_url = res.url
                
                if final_url and final_url != href:
                    final_parsed = urllib.parse.urlparse(final_url)
                    final_netloc = final_parsed.netloc.lower()
                    
                    fact_unshorten = _fact(f"fact_unshorten_{i}", "url_unshortened", SignalState.PRESENT, final_url, f"Shortened link {href} resolves to {final_url}")
                    facts.append(fact_unshorten)
                    
                    # Update netloc to check the true destination's IP in AbuseIPDB
                    netloc = final_netloc
            except Exception:
                pass # If unshortening fails, just continue with the original netloc
            
        # Try resolving the domain to an IP
        try:
            ip_address = socket.gethostbyname(netloc)
        except Exception:
            continue
            
        if ip_address in checked_ips:
            continue
        checked_ips.add(ip_address)
            
        # Check against AbuseIPDB
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        
        try:
            response = requests.request(method='GET', url=url, headers=headers, params=querystring, timeout=5)
            if response.status_code == 200:
                data = response.json().get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                
                if score > 0:
                    detail = f"AbuseIPDB reports {score}% confidence of malicious activity for {ip_address} ({netloc})"
                    fact_ti = _fact(f"fact_ti_{i}", "abuseipdb_malicious_ip", SignalState.PRESENT, ip_address, detail)
                    facts.append(fact_ti)
                    
                    if score >= 90:
                        candidates.append(_candidate(
                            "CONFIRMED_MALICIOUS_INDICATOR",
                            "Strong",
                            ip_address,
                            "abuseipdb",
                            "exact_confirmed_malicious_indicator",
                            [fact_ti.fact_id],
                            detail
                        ))
                    elif score >= 50:
                        candidates.append(_candidate(
                            "GENERIC_SUSPICION",
                            "Weak",
                            ip_address,
                            "abuseipdb",
                            "generic_suspicious_content",
                            [fact_ti.fact_id],
                            detail
                        ))
        except Exception as e:
            # Silently handle network timeouts or errors to avoid crashing the pipeline
            pass

    return AnalyzerOutput(
        analyzer_name=ANALYZER_NAME,
        analyzer_version=ANALYZER_VERSION,
        facts=facts,
        candidates=candidates,
    )
