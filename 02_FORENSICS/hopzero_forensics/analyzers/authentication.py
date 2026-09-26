"""
Authentication Analyzer (Deterministic)
=======================================

Parses and validates SPF, DKIM, DMARC, and identifier alignment from email
headers (Authentication-Results, Received-SPF, DKIM-Signature).

Hard rules:
  * Authentication PASS produces 0 points (no negative scoring).
  * Distinguishes PRESENT / ABSENT / UNAVAILABLE.
  * Emits deterministic Facts and FindingCandidates with locked vocabulary.
"""
from __future__ import annotations
import re
from typing import Optional, List, Tuple
from ..interfaces import AnalyzerOutput, CanonicalEmail, Fact, FindingCandidate, SignalState

ANALYZER_NAME = "authentication_analyzer"
ANALYZER_VERSION = "1.0"
VOCAB_VERSION = "v1"

def _fact(fid: str, key: str, state: SignalState, value: Optional[str], detail: Optional[str] = None) -> Fact:
    return Fact(
        fact_id=fid,
        category="Authentication",
        key=key,
        state=state,
        value=value,
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
        detail=detail,
    )

def _candidate(code: str, strength: str, subject: str, target: str, claim_sig: str, facts: List[str], text: Optional[str] = None) -> FindingCandidate:
    return FindingCandidate(
        category="Authentication",
        qualification_code=code,
        qualification_version=VOCAB_VERSION,
        strength=strength,
        normalized_subject=subject,
        normalized_target=target,
        claim_signature=claim_sig,
        supporting_fact_ids=facts,
        supporting_text=text or f"Authentication result for {subject}: {code}",
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
    )

def analyze_authentication(email: CanonicalEmail) -> AnalyzerOutput:
    facts: List[Fact] = []
    candidates: List[FindingCandidate] = []

    auth_headers = [h.value for h in email.headers if h.name.lower() == "authentication-results"]
    spf_headers = [h.value for h in email.headers if h.name.lower() == "received-spf"]
    dkim_sig_headers = [h for h in email.headers if h.name.lower() == "dkim-signature"]

    from_domain = None
    if email.from_addresses and email.from_addresses[0].address:
        addr = email.from_addresses[0].address
        if "@" in addr:
            from_domain = addr.split("@")[-1].lower()

    # 1. SPF Analysis
    spf_result = SignalState.UNAVAILABLE
    spf_value = None
    spf_details = None

    # Check Authentication-Results first
    for h in auth_headers:
        m = re.search(r"(?:^|[;\s])spf=(pass|fail|softfail|neutral|none|permerror|temperror)(?:[;\s]|$)", h, re.IGNORECASE)
        if m:
            spf_value = m.group(1).lower()
            spf_result = SignalState.PRESENT
            spf_details = f"from Authentication-Results: {m.group(0).strip()}"
            break

    # If not in auth-results, check Received-SPF
    if spf_result == SignalState.UNAVAILABLE and spf_headers:
        m = re.match(r"^\s*(pass|fail|softfail|neutral|none|permerror|temperror)\b", spf_headers[0], re.IGNORECASE)
        if m:
            spf_value = m.group(1).lower()
            spf_result = SignalState.PRESENT
            spf_details = f"from Received-SPF: {spf_headers[0][:80]}"

    if spf_result == SignalState.UNAVAILABLE:
        if not auth_headers and not spf_headers:
            spf_result = SignalState.ABSENT
            spf_value = "none"
            spf_details = "No SPF verification headers present"
        else:
            spf_value = "unavailable"

    fact_spf = _fact("fact_auth_spf_01", "spf_result", spf_result, spf_value, spf_details)
    facts.append(fact_spf)

    # 2. DKIM Analysis
    dkim_result = SignalState.UNAVAILABLE
    dkim_value = None
    dkim_details = None

    for h in auth_headers:
        m = re.search(r"(?:^|[;\s])dkim=(pass|fail|none|invalid|permerror|temperror)(?:[;\s]|$)", h, re.IGNORECASE)
        if m:
            dkim_value = m.group(1).lower()
            dkim_result = SignalState.PRESENT
            dkim_details = f"from Authentication-Results: {m.group(0).strip()}"
            break

    if dkim_result == SignalState.UNAVAILABLE:
        if not dkim_sig_headers:
            dkim_result = SignalState.ABSENT
            dkim_value = "none"
            dkim_details = "No DKIM-Signature header present"
        else:
            dkim_result = SignalState.PRESENT
            dkim_value = "unverified"
            dkim_details = "DKIM-Signature header present but unverified by receiver"

    fact_dkim = _fact("fact_auth_dkim_01", "dkim_result", dkim_result, dkim_value, dkim_details)
    facts.append(fact_dkim)

    # 3. DMARC Analysis
    dmarc_result = SignalState.UNAVAILABLE
    dmarc_value = None
    dmarc_details = None

    for h in auth_headers:
        m = re.search(r"(?:^|[;\s])dmarc=(pass|fail|none|permerror|temperror)(?:[;\s]|$)", h, re.IGNORECASE)
        if m:
            dmarc_value = m.group(1).lower()
            dmarc_result = SignalState.PRESENT
            dmarc_details = f"from Authentication-Results: {m.group(0).strip()}"
            break

    if dmarc_result == SignalState.UNAVAILABLE:
        dmarc_result = SignalState.ABSENT
        dmarc_value = "none"
        dmarc_details = "No DMARC evaluation in Authentication-Results"

    fact_dmarc = _fact("fact_auth_dmarc_01", "dmarc_result", dmarc_result, dmarc_value, dmarc_details)
    facts.append(fact_dmarc)

    # 4. Identifier Alignment Check
    alignment_ok = True
    alignment_detail = "Aligned"
    if from_domain:
        # Check DKIM d= tag if present in DKIM-Signature headers
        for sig_hdr in dkim_sig_headers:
            val = sig_hdr.value if hasattr(sig_hdr, "value") else str(sig_hdr)
            m = re.search(r"(?:^|[;\s])d=([^;\s]+)", val, re.IGNORECASE)
            if m:
                dkim_domain = m.group(1).strip().lower()
                if from_domain != dkim_domain and not from_domain.endswith("." + dkim_domain):
                    alignment_ok = False
                    alignment_detail = f"DKIM d={dkim_domain} does not align with From={from_domain}"
                    break
        # Also check Authentication-Results header.i or header.d if alignment still ok
        if alignment_ok:
            for ah in auth_headers:
                m_d = re.search(r"header\.d=([^;\s]+)", ah, re.IGNORECASE)
                m_i = re.search(r"header\.i=@?([^;\s]+)", ah, re.IGNORECASE)
                auth_dkim_domain = (m_d.group(1) if m_d else (m_i.group(1) if m_i else None))
                if auth_dkim_domain:
                    auth_dkim_domain = auth_dkim_domain.strip().lower()
                    if from_domain != auth_dkim_domain and not from_domain.endswith("." + auth_dkim_domain):
                        alignment_ok = False
                        alignment_detail = f"DKIM header identity {auth_dkim_domain} does not align with From={from_domain}"
                        break

    fact_align = _fact(
        "fact_auth_align_01",
        "identifier_alignment",
        SignalState.PRESENT if from_domain else SignalState.UNAVAILABLE,
        "aligned" if alignment_ok else "misaligned",
        alignment_detail,
    )
    facts.append(fact_align)

    # Generate FindingCandidates (NO negative points for pass)
    domain_str = from_domain or "unknown_domain"

    if spf_value in ("fail", "softfail"):
        candidates.append(
            _candidate("SPF_FAIL", "Moderate", domain_str, "spf", "spf_validation_fail", [fact_spf.fact_id])
        )
    elif spf_value == "none":
        candidates.append(
            _candidate("SPF_NONE", "Weak", domain_str, "spf", "spf_record_none", [fact_spf.fact_id])
        )

    if dkim_value in ("fail", "invalid"):
        candidates.append(
            _candidate("DKIM_FAIL", "Moderate", domain_str, "dkim", "dkim_signature_fail", [fact_dkim.fact_id])
        )
    elif dkim_value == "none":
        candidates.append(
            _candidate("DKIM_NONE", "Weak", domain_str, "dkim", "dkim_signature_none", [fact_dkim.fact_id])
        )

    if dmarc_value == "fail":
        candidates.append(
            _candidate("DMARC_FAIL", "Moderate", domain_str, "dmarc", "dmarc_validation_fail", [fact_dmarc.fact_id])
        )
    elif dmarc_value == "none":
        candidates.append(
            _candidate("DMARC_NONE", "Weak", domain_str, "dmarc", "dmarc_policy_none", [fact_dmarc.fact_id])
        )

    if not alignment_ok:
        candidates.append(
            _candidate(
                "IDENTIFIER_ALIGNMENT_FAILURE",
                "Moderate",
                domain_str,
                "alignment",
                "identifier_alignment_mismatch",
                [fact_align.fact_id],
                alignment_detail,
            )
        )

    return AnalyzerOutput(
        analyzer_name=ANALYZER_NAME,
        analyzer_version=ANALYZER_VERSION,
        facts=facts,
        candidates=candidates,
    )