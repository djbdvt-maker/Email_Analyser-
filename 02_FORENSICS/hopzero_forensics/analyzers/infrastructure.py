from __future__ import annotations
import ipaddress
from typing import Optional, List
from ..interfaces import AnalyzerOutput, CanonicalEmail, Fact, FindingCandidate, SignalState
from ..config.infrastructure_reputation_v1 import (
    KNOWN_BAD_ASNS, BULLETPROOF_PREFIXES, INFRASTRUCTURE_REPUTATION_VERSION
)

ANALYZER_NAME = "infrastructure_analyzer"
ANALYZER_VERSION = "1.0"
VOCAB_VERSION = "v1"

def _fact(fid: str, key: str, state: SignalState, value: Optional[str], detail: Optional[str] = None) -> Fact:
    return Fact(
        fact_id=fid,
        category="Infrastructure",
        key=key,
        state=state,
        value=value,
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
        detail=detail,
    )

def _candidate(code: str, strength: str, subject: str, target: str, claim_sig: str, facts: List[str], text: Optional[str] = None) -> FindingCandidate:
    return FindingCandidate(
        category="Infrastructure",
        qualification_code=code,
        qualification_version=VOCAB_VERSION,
        strength=strength,
        normalized_subject=subject,
        normalized_target=target,
        claim_signature=claim_sig,
        supporting_fact_ids=facts,
        supporting_text=text or f"Infrastructure finding {code} for {subject}",
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
    )

def _is_ip_in_prefixes(ip_str: str, prefixes: tuple[str, ...]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        for prefix in prefixes:
            if "/" in prefix:
                if ip in ipaddress.ip_network(prefix, strict=False):
                    return True
            else:
                if str(ip) == prefix:
                    return True
    except ValueError:
        pass
    return False

def analyze_infrastructure(email: CanonicalEmail, probable_origin_ip: Optional[str] = None) -> AnalyzerOutput:
    facts: List[Fact] = []
    candidates: List[FindingCandidate] = []

    target_ip = probable_origin_ip
    if not target_ip:
        if email.received_chain_raw:
            for hop in reversed(email.received_chain_raw):
                if hop.observed_ip:
                    target_ip = hop.observed_ip
                    break

    if not target_ip:
        facts.append(_fact("fact_infra_ip_01", "origin_ip", SignalState.UNAVAILABLE, None, "No candidate origin IP available"))
        return AnalyzerOutput(
            analyzer_name=ANALYZER_NAME,
            analyzer_version=ANALYZER_VERSION,
            facts=facts,
            candidates=candidates,
        )

    fact_ip = _fact("fact_infra_ip_01", "candidate_probable_origin_ip", SignalState.PRESENT, target_ip, f"Candidate probable-origin IP: {target_ip}")
    facts.append(fact_ip)

    import os
    import urllib.request
    import json
    import re
    from datetime import datetime, timezone

    detected_asn = None
    if email.headers:
        for h in email.headers:
            m = re.search(r"\b(?:AS|ASN)\s*[:=]?\s*(\d{2,6})\b", h.value, re.IGNORECASE)
            if m:
                detected_asn = int(m.group(1))
                break

    rapidapi_key = os.environ.get("HOPZERO_RAPIDAPI_KEY")
    live_threat_intel_hit = False
    live_threat_detail = ""
    
    network_types = []
    api_unavailable = False
    api_unavailable_reason = ""
    
    if rapidapi_key:
        try:
            url = f"https://email-forensics-investigation-api.p.rapidapi.com/url/?url={target_ip}"
            headers = {
                "x-rapidapi-host": "email-forensics-investigation-api.p.rapidapi.com",
                "x-rapidapi-key": rapidapi_key,
                "Content-Type": "application/json"
            }
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=3.0) as response:
                resp_data = json.loads(response.read().decode())
                
                if resp_data.get("malicious", False) or resp_data.get("risk_score", 0) > 80:
                    live_threat_intel_hit = True
                    live_threat_detail = f"RapidAPI Intelligence flagged origin IP {target_ip} as malicious."
                    
                if resp_data.get("is_vpn"):
                    network_types.append("VPN")
                if resp_data.get("is_proxy"):
                    network_types.append("PROXY")
                if resp_data.get("is_tor"):
                    network_types.append("TOR")
                    
        except Exception as e:
            api_unavailable = True
            api_unavailable_reason = f"Provider request failed: {str(e)}"
    else:
        api_unavailable = True
        api_unavailable_reason = "No RapidAPI credential configured in environment."

    if api_unavailable:
        facts.append(_fact("fact_infra_api_state", "external_intelligence_provider", SignalState.UNAVAILABLE, None, f"State = unavailable. {api_unavailable_reason} at {datetime.now(timezone.utc).isoformat()}"))
    else:
        facts.append(_fact("fact_infra_api_state", "external_intelligence_provider", SignalState.PRESENT, "available", "Provider returned successfully."))

    # 1. Network Type Semantics
    if network_types:
        for net_type in network_types:
            fact_nt = _fact(f"fact_infra_net_{net_type.lower()}", "network_type", SignalState.PRESENT, net_type, f"RapidAPI identified {target_ip} as an active {net_type} node.")
            facts.append(fact_nt)
    else:
        if not api_unavailable:
            facts.append(_fact("fact_infra_net_none", "network_type", SignalState.ABSENT, None, "No VPN/Proxy/Tor detected by provider."))

    # 2. Bulletproof Hosting Check (Static Subnets ONLY - VPN does not mean Bulletproof Hosting)
    if _is_ip_in_prefixes(target_ip, BULLETPROOF_PREFIXES):
        detail = f"Origin IP '{target_ip}' matches known bulletproof hosting subnet ({INFRASTRUCTURE_REPUTATION_VERSION})"
        fact_bp = _fact("fact_infra_bp_01", "bulletproof_hosting_match", SignalState.PRESENT, target_ip, detail)
        facts.append(fact_bp)
        candidates.append(
            _candidate(
                "BULLETPROOF_HOSTING_MATCH",
                "Moderate",
                target_ip,
                "bulletproof_hosting",
                "bulletproof_hosting_network_match",
                [fact_bp.fact_id],
                detail,
            )
        )
    else:
        facts.append(_fact("fact_infra_bp_01", "bulletproof_hosting_match", SignalState.ABSENT, None, "IP not flagged as Bulletproof Hosting by static list"))

    # 3. Malicious IP & Known Bad ASN Check
    if live_threat_intel_hit:
        fact_api = _fact("fact_infra_api_01", "live_threat_intelligence", SignalState.PRESENT, target_ip, live_threat_detail)
        facts.append(fact_api)
        candidates.append(
            _candidate(
                "CONFIRMED_MALICIOUS_INDICATOR",
                "Strong",
                target_ip,
                "rapidapi_threat_intel",
                "exact_confirmed_malicious_indicator",
                [fact_api.fact_id],
                live_threat_detail,
            )
        )
    elif detected_asn is not None:
        if detected_asn in KNOWN_BAD_ASNS:
            bad_asn_info = KNOWN_BAD_ASNS[detected_asn]
            detail = f"Origin ASN {detected_asn} ({bad_asn_info.name}) matches known malicious ASN list"
            fact_asn = _fact("fact_infra_asn_01", "known_bad_asn", SignalState.PRESENT, str(detected_asn), detail)
            facts.append(fact_asn)
            candidates.append(
                _candidate(
                    "KNOWN_BAD_ASN",
                    "Moderate",
                    str(detected_asn),
                    bad_asn_info.name,
                    "origin_ip_in_known_bad_asn",
                    [fact_asn.fact_id],
                    detail,
                )
            )
        else:
            facts.append(_fact("fact_infra_asn_01", "known_bad_asn", SignalState.ABSENT, str(detected_asn), f"ASN {detected_asn} not in known bad ASN database"))
    else:
        facts.append(_fact("fact_infra_asn_01", "known_bad_asn", SignalState.UNAVAILABLE, None, "ASN telemetry unavailable in static offline headers"))

    # 4. Reverse DNS (rDNS / PTR) - offline static mode
    facts.append(
        _fact("fact_infra_rdns_01", "reverse_dns_ptr", SignalState.UNAVAILABLE, None, "rDNS/PTR verification unavailable in static offline mode")
    )

    # 5. Newly Observed Infrastructure - offline static mode
    facts.append(
        _fact("fact_infra_new_01", "newly_observed_infrastructure", SignalState.UNAVAILABLE, None, "First-seen IP telemetry unavailable in static offline mode")
    )

    return AnalyzerOutput(
        analyzer_name=ANALYZER_NAME,
        analyzer_version=ANALYZER_VERSION,
        facts=facts,
        candidates=candidates,
    )
