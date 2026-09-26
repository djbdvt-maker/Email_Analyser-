"""
Deterministic Conclusion Generator (Phase 7 locked specification).

Strictly emits only the 4 canonical verdicts:
  - BENIGN: Available evidence supports a non-malicious interpretation and no material unresolved evidence prevents that conclusion.
  - SUSPICIOUS: Meaningful suspicious/deceptive evidence exists, but maliciousness is not sufficiently established.
  - MALICIOUS: Sufficient high-confidence evidence establishes malicious behavior or a confirmed malicious indicator (e.g. CF-05).
  - INDETERMINATE: Available evidence is insufficient or materially unavailable to support a reliable determination.

Important Invariants:
  - HIGH / CRITICAL does NOT automatically mean MALICIOUS.
  - CF-01 through CF-06 do NOT automatically mean MALICIOUS merely because they produce HIGH.
  - CF-05 confirmed malicious evidence is a direct basis for MALICIOUS.
  - Missing evidence must never be treated as clean.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Any


CANONICAL_VERDICTS = {"BENIGN", "SUSPICIOUS", "MALICIOUS", "INDETERMINATE"}


@dataclass
class ConclusionOutput:
    verdict: str  # Strictly "BENIGN" | "SUSPICIOUS" | "MALICIOUS" | "INDETERMINATE"
    one_line_explanation: str
    why_explanation: str
    conclusion: str = ""
    explanation: str = ""
    supporting_finding_ids: List[str] = field(default_factory=list)
    generator_version: str = "conclusion-generator-v2"
    provenance: dict = field(default_factory=dict)


class ConclusionGenerator:
    """
    Deterministic rule/template-based conclusion generator.
    Produces structured, human-readable conclusion narratives and canonical verdicts.
    """
    def generate(
        self,
        score_output: Optional[Any] = None,
        *,
        total_score: Optional[int] = None,
        severity: Optional[str] = None,
        triggered_floor_codes: Optional[List[str]] = None,
        finding_ids: Optional[List[str]] = None,
        findings: Optional[list] = None,
        ai_status: Optional[str] = None,
        is_indeterminate: bool = False,
    ) -> ConclusionOutput:
        if score_output is not None:
            if total_score is None:
                total_score = getattr(score_output, "total_score", 0)
            if severity is None:
                severity = getattr(score_output, "severity", "LOW")
            if triggered_floor_codes is None:
                triggered_floor_codes = getattr(score_output, "triggered_floor_codes", [])
            if finding_ids is None:
                finding_ids = getattr(score_output, "finding_ids_used", [])

        total_score = total_score if total_score is not None else 0
        raw_sev = severity if severity is not None else "LOW"
        severity = raw_sev.upper()
        triggered = triggered_floor_codes or []

        # Check for confirmed malicious indicator in findings
        has_confirmed_malicious = False
        if findings:
            for f in findings:
                q_code = getattr(f, "qualification_code", "")
                if q_code == "CONFIRMED_MALICIOUS_INDICATOR":
                    has_confirmed_malicious = True
                    break

        # -------------------------------------------------------------
        # Verdict Determination (Strict Phase 7 Semantics)
        # -------------------------------------------------------------
        if is_indeterminate:
            verdict = "INDETERMINATE"
            one_line = f"INDETERMINATE: Available evidence is insufficient or materially unavailable ({total_score}/100)"
            why = (
                "Key email transmission evidence or forensic signals were missing or unavailable, "
                "preventing a reliable benign, suspicious, or malicious determination."
            )
        elif "CF-05" in triggered or has_confirmed_malicious:
            verdict = "MALICIOUS"
            one_line = f"MALICIOUS: High-confidence malicious indicator confirmed ({total_score}/100)"
            why = (
                "Forensic inspection identified exact confirmed malicious indicators "
                "matching verified threat intelligence or threat signatures."
            )
        elif triggered:
            verdict = "SUSPICIOUS"
            if "CF-01" in triggered:
                one_line = f"SUSPICIOUS: Lookalike domain with explicit brand representation claim ({total_score}/100, {severity})"
                why = (
                    "Domain analysis identified a protected-brand lookalike domain combined with "
                    "explicit claims representing the same protected brand."
                )
            elif "CF-02" in triggered:
                one_line = f"SUSPICIOUS: Executive impersonation combined with financial request ({total_score}/100, {severity})"
                why = (
                    "Identity and content analysis detected executive display-name impersonation "
                    "paired with requests for financial transfers or invoice alteration."
                )
            elif "CF-03" in triggered:
                one_line = f"SUSPICIOUS: Credential phishing link combined with identity anomaly ({total_score}/100, {severity})"
                why = (
                    "Forensic link inspection detected credential-harvesting indicators combined with "
                    "sender identity anomalies."
                )
            elif "CF-04" in triggered:
                one_line = f"SUSPICIOUS: High-risk attachment paired with sender anomaly ({total_score}/100, {severity})"
                why = (
                    "Attachment inspection detected executable or macro-enabled attachments paired with "
                    "suspicious sender identity context."
                )
            elif "CF-06" in triggered:
                one_line = f"SUSPICIOUS: Qualified routing contradiction detected across Received headers ({total_score}/100, {severity})"
                why = (
                    "Forensic routing inspection identified qualified routing contradiction across "
                    "Received headers or contiguous trusted receiving boundaries."
                )
            else:
                one_line = f"SUSPICIOUS: Critical forensic floor triggered ({total_score}/100, {severity})"
                why = f"Forensic analysis triggered security floor {triggered} raising severity to {severity}."
        elif total_score == 0 and not findings:
            verdict = "BENIGN"
            one_line = f"BENIGN: Available evidence supports a non-malicious interpretation (0/100, {severity})"
            why = (
                "All evaluated forensic categories (routing, authentication, domain, identity, URL, "
                "attachment, infrastructure, social engineering) conformed to benign baseline standards "
                "with no suspicious indicators identified."
            )
        else:
            verdict = "SUSPICIOUS"
            one_line = f"SUSPICIOUS: Meaningful suspicious anomalies observed ({total_score}/100, {severity})"
            why = (
                f"Accumulated forensic findings reached {severity} threshold ({total_score}/100) "
                "across evaluated indicators without establishing confirmed maliciousness."
            )

        # Append AI degradation explanation if applicable
        if ai_status and ai_status.lower() in (
            "unavailable", "ai_unavailable", "degraded", "offline",
            "err_ai_unavailable_timeout", "err_ai_unavailable_malformed",
            "err_ai_unavailable_upstream", "timeout", "invalid_response",
        ):
            from app.services.ai_reasoner_service import AI_UNAVAILABLE_EXPLANATION
            why += f" {AI_UNAVAILABLE_EXPLANATION}"

        supporting_fids = []
        if findings:
            supporting_fids = [str(getattr(f, "id", f)) for f in findings if getattr(f, "id", None)]
        elif finding_ids:
            supporting_fids = [str(fid) for fid in finding_ids]

        conclusion_full = f"{one_line} {why}".strip()
        gen_ver = "conclusion-generator-v2"
        prov = {
            "generator_version": gen_ver,
            "engine_version": getattr(score_output, "engine_version", "score-engine-v2"),
            "supporting_finding_ids": supporting_fids,
        }

        return ConclusionOutput(
            verdict=verdict,
            one_line_explanation=one_line,
            why_explanation=why,
            conclusion=conclusion_full,
            explanation=why,
            supporting_finding_ids=supporting_fids,
            generator_version=gen_ver,
            provenance=prov,
        )
