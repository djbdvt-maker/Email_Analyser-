"""
Identity Analyzer (Deterministic)
=================================

Compares From, Reply-To, and Return-Path addresses and display names for
structural inconsistency and executive/brand impersonation.

Hard rules:
  * Display-name vs sender mismatch = Weak.
  * Reply-To mismatch = Moderate.
  * Return-Path mismatch = Moderate.
  * Executive claim = Strong when combined with address mismatch.
  * Uses NormalizedEvidence for display-name text comparisons to resist obfuscation.
"""
from __future__ import annotations
from typing import Optional, List
from ..interfaces import AnalyzerOutput, CanonicalEmail, Fact, FindingCandidate, SignalState
from ..config.protected_brands_v1 import PROTECTED_BRANDS

ANALYZER_NAME = "identity_analyzer"
ANALYZER_VERSION = "1.0"
VOCAB_VERSION = "v1"

def _fact(fid: str, key: str, state: SignalState, value: Optional[str], detail: Optional[str] = None) -> Fact:
    return Fact(
        fact_id=fid,
        category="Identity",
        key=key,
        state=state,
        value=value,
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
        detail=detail,
    )

def _candidate(code: str, strength: str, subject: str, target: str, claim_sig: str, facts: List[str], text: Optional[str] = None) -> FindingCandidate:
    return FindingCandidate(
        category="Identity",
        qualification_code=code,
        qualification_version=VOCAB_VERSION,
        strength=strength,
        normalized_subject=subject,
        normalized_target=target,
        claim_signature=claim_sig,
        supporting_fact_ids=facts,
        supporting_text=text or f"Identity inconsistency: {code} for {subject}",
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
    )

def analyze_identity(email: CanonicalEmail, normalized_evidence=None) -> AnalyzerOutput:
    facts: List[Fact] = []
    candidates: List[FindingCandidate] = []

    from_addr = email.from_addresses[0] if email.from_addresses else None
    reply_to = email.reply_to_addresses[0] if email.reply_to_addresses else None
    return_path = email.return_path

    from_email = (from_addr.address or "").lower() if from_addr else ""
    from_display = from_addr.display_name or "" if from_addr else ""
    reply_email = (reply_to.address or "").lower() if reply_to else ""
    return_email = (return_path.address or "").lower() if return_path else ""

    # Check if normalized evidence is available for display name
    if normalized_evidence and hasattr(normalized_evidence, "fields"):
        for nf in normalized_evidence.fields:
            if "from_addresses" in nf.field_path and "display_name" in nf.field_path:
                from_display = nf.normalized_text or from_display

    from_domain = from_email.split("@")[-1] if "@" in from_email else ""
    reply_domain = reply_email.split("@")[-1] if "@" in reply_email else ""
    return_domain = return_email.split("@")[-1] if "@" in return_email else ""

    # 1. Reply-To vs From Check
    if reply_email and from_email and reply_email != from_email:
        mismatch_desc = f"Reply-To ({reply_email}) differs from From ({from_email})"
        fact_rt = _fact("fact_id_replyto_01", "reply_to_mismatch", SignalState.PRESENT, reply_email, mismatch_desc)
        facts.append(fact_rt)

        candidates.append(
            _candidate(
                "IDENTITY_REPLY_TO_MISMATCH",
                "Moderate",
                from_email,
                reply_email,
                "reply_to_from_mismatch",
                [fact_rt.fact_id],
                mismatch_desc,
            )
        )
    else:
        facts.append(_fact("fact_id_replyto_01", "reply_to_mismatch", SignalState.ABSENT, None, "Reply-To matches From or absent"))

    # 2. Return-Path vs From Check
    if return_email and from_email and return_domain != from_domain:
        rp_desc = f"Return-Path domain ({return_domain}) materially differs from From domain ({from_domain})"
        fact_rp = _fact("fact_id_returnpath_01", "return_path_mismatch", SignalState.PRESENT, return_email, rp_desc)
        facts.append(fact_rp)

        candidates.append(
            _candidate(
                "IDENTITY_RETURN_PATH_MISMATCH",
                "Moderate",
                from_email,
                return_email,
                "return_path_from_mismatch",
                [fact_rp.fact_id],
                rp_desc,
            )
        )
    else:
        facts.append(_fact("fact_id_returnpath_01", "return_path_mismatch", SignalState.ABSENT, None, "Return-Path domain matches or absent"))

    # 3. Display-Name Impersonation / Mismatch Check
    has_exec_claim = False
    has_brand_claim = False
    claimed_target = ""

    # Executive title or known executive name check in display name
    exec_titles = [
        "ceo", "cfo", "chief executive", "president", "director", "managing director",
        "executive", "billing", "billing department", "payroll", "finance", "accounting"
    ]
    display_lower = from_display.lower()

    for brand_id, brand in PROTECTED_BRANDS.items():
        for exec_name in brand.executives:
            if exec_name.lower() in display_lower:
                has_exec_claim = True
                claimed_target = exec_name
                break
        if has_exec_claim:
            break
        for b_name in brand.display_names:
            if b_name.lower() in display_lower:
                has_brand_claim = True
                claimed_target = b_name
                break

    if not has_exec_claim:
        for title in exec_titles:
            if title in display_lower.split() or title in display_lower:
                has_exec_claim = True
                claimed_target = f"Authority Title ({title})"
                break

    if (has_exec_claim or has_brand_claim) and from_domain:
        # Check if from_domain belongs to the brand
        is_legit = False
        for brand in PROTECTED_BRANDS.values():
            if from_domain in brand.protected_domains or from_domain in brand.legitimate_alternates:
                is_legit = True
                break

        if not is_legit:
            if has_exec_claim:
                f_desc = f"Display name '{from_display}' claims executive authority but sending domain is '{from_domain}'"
                fact_exec = _fact("fact_id_exec_01", "executive_display_name_claim", SignalState.PRESENT, from_display, f_desc)
                facts.append(fact_exec)
                candidates.append(
                    _candidate(
                        "EXECUTIVE_IMPERSONATION",
                        "Strong",
                        from_display,
                        claimed_target,
                        "executive_display_name_claim",
                        [fact_exec.fact_id],
                        f_desc,
                    )
                )
                candidates.append(
                    _candidate(
                        "IDENTITY_ANOMALY",
                        "Moderate",
                        from_email,
                        claimed_target,
                        "sender_identity_anomaly",
                        [fact_exec.fact_id],
                        f_desc,
                    )
                )
            elif has_brand_claim:
                f_desc = f"Display name '{from_display}' claims brand identity '{claimed_target}' but domain is '{from_domain}'"
                fact_brand = _fact("fact_id_brand_01", "brand_display_name_claim", SignalState.PRESENT, from_display, f_desc)
                facts.append(fact_brand)
                candidates.append(
                    _candidate(
                        "EXPLICIT_BRAND_REPRESENTATION_CLAIM",
                        "Moderate",
                        from_display,
                        claimed_target,
                        "explicit_brand_claim",
                        [fact_brand.fact_id],
                        f_desc,
                    )
                )
                candidates.append(
                    _candidate(
                        "IDENTITY_ANOMALY",
                        "Moderate",
                        from_email,
                        claimed_target,
                        "sender_identity_anomaly",
                        [fact_brand.fact_id],
                        f_desc,
                    )
                )

    elif from_display and "@" in from_display and from_email not in from_display:
        # Display name contains an embedded email that differs from envelope From
        f_desc = f"Display name embeds an address '{from_display}' differing from envelope From '{from_email}'"
        fact_disp = _fact("fact_id_disp_01", "display_name_mismatch", SignalState.PRESENT, from_display, f_desc)
        facts.append(fact_disp)
        candidates.append(
            _candidate(
                "IDENTITY_DISPLAY_NAME_MISMATCH",
                "Weak",
                from_display,
                from_email,
                "display_name_sender_mismatch",
                [fact_disp.fact_id],
                f_desc,
            )
        )

    return AnalyzerOutput(
        analyzer_name=ANALYZER_NAME,
        analyzer_version=ANALYZER_VERSION,
        facts=facts,
        candidates=candidates,
    )