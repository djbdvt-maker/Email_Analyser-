"""
Laya Pre-Screen Service.
========================

Fast (~35ms) non-autoregressive pre-screening layer that runs AFTER the 7
deterministic forensic analyzers and BEFORE the expensive LLM-based AI Reasoner.

Uses the laya library's Router to produce typed decisions:
- threat_category (choice): phishing, BEC, malware, spam, or benign
- urgency (score): 0..2 rubric → routine / soon / critical
- social_engineering (noul): binary yes/no
- financial_request (noul): binary yes/no
- credential_harvesting (noul): binary yes/no
- executive_impersonation (noul): binary yes/no

Architectural invariants:
- Laya signals are ADVISORY ONLY.  They are persisted as Facts with
  produced_by="laya_prescreen" but NEVER create Findings, modify the
  numeric score, alter severity, or influence floor evaluation.
- When Laya classifies an email as "benign" with high confidence, the
  pipeline MAY skip the expensive LLM AI Reasoner call (configurable).
- Full fault tolerance: if Laya fails for any reason, the pipeline
  proceeds unchanged (same pattern as the AI Reasoner fallback).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Singleton Router with lazy initialization
# ---------------------------------------------------------------------------
_router = None
_router_init_attempted = False


def _get_router():
    """
    Lazy-initialize the laya Router singleton.  Preloads checkpoints on
    first call so subsequent predict() calls hit sub-35ms latency.
    """
    global _router, _router_init_attempted
    if _router is not None:
        return _router
    if _router_init_attempted:
        # Already failed once; don't retry every request
        return None
    _router_init_attempted = True
    try:
        from laya import Router
        _router = Router(preload=True)
        logger.info("Laya Router initialized and checkpoints preloaded")
        return _router
    except Exception as exc:
        logger.warning(f"Laya Router initialization failed (pre-screening disabled): {exc}")
        return None


# ---------------------------------------------------------------------------
# Question definitions — mapped to HopZero forensic categories
# ---------------------------------------------------------------------------
LAYA_QUESTIONS: Dict[str, Dict[str, Any]] = {
    "threat_category": {
        "type": "choice",
        "instructions": "What is the primary threat category of this email?",
        "criteria": {
            "phishing": "credential theft, fake login pages, verification requests",
            "bec": "business email compromise, executive impersonation, invoice fraud, wire transfer",
            "malware": "malicious attachments, suspicious downloads, trojan, ransomware",
            "spam": "unsolicited advertising, bulk marketing, unwanted newsletters",
            "benign": "legitimate business correspondence, no threat indicators",
        },
    },
    "urgency": {
        "type": "score",
        "instructions": "How urgently does this email require security review?",
        "criteria": [
            "routine correspondence, no time pressure",
            "moderately time-sensitive, should be reviewed soon",
            "critical deadline, blocking issue, or active threat requiring immediate action",
        ],
    },
    "social_engineering": {
        "type": "noul",
        "instructions": (
            "Does this email use social engineering tactics such as urgency pressure, "
            "authority claims, fear of consequences, or artificial scarcity?"
        ),
    },
    "financial_request": {
        "type": "noul",
        "instructions": (
            "Does this email explicitly request financial action such as wire transfer, "
            "payment, invoice processing, or bank detail changes?"
        ),
    },
    "credential_harvesting": {
        "type": "noul",
        "instructions": (
            "Does this email attempt to harvest credentials by directing the recipient "
            "to a login page, asking for passwords, or requesting account verification?"
        ),
    },
    "executive_impersonation": {
        "type": "noul",
        "instructions": (
            "Does the sender impersonate or claim authority as a C-suite executive, "
            "managing director, or senior leadership figure?"
        ),
    },
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class LayaPrescreenResult:
    """Structured output of the Laya pre-screening pass."""

    # Primary classification
    threat_category: str = "unknown"
    threat_category_confidence: float = 0.0

    # Urgency (0.0 = routine, 1.0 = moderate, 2.0 = critical)
    urgency_level: float = 0.0

    # Binary signals (probability 0..1)
    social_engineering_probability: float = 0.0
    financial_request_probability: float = 0.0
    credential_harvesting_probability: float = 0.0
    executive_impersonation_probability: float = 0.0

    # Routing metadata
    model_used: str = "unknown"
    latency_ms: float = 0.0
    status: str = "success"  # "success" | "error" | "disabled"
    error: Optional[str] = None

    # Derived convenience flag
    is_likely_benign: bool = False
    skip_ai_recommended: bool = False

    def to_fact_payload(self) -> Dict[str, Any]:
        """Serialize to a dict suitable for persisting as a Fact payload."""
        return {
            "threat_category": self.threat_category,
            "threat_category_confidence": round(self.threat_category_confidence, 4),
            "urgency_level": round(self.urgency_level, 4),
            "social_engineering_probability": round(self.social_engineering_probability, 4),
            "financial_request_probability": round(self.financial_request_probability, 4),
            "credential_harvesting_probability": round(self.credential_harvesting_probability, 4),
            "executive_impersonation_probability": round(self.executive_impersonation_probability, 4),
            "model_used": self.model_used,
            "latency_ms": round(self.latency_ms, 2),
            "status": self.status,
            "error": self.error,
            "is_likely_benign": self.is_likely_benign,
            "skip_ai_recommended": self.skip_ai_recommended,
        }


def _extract_choice_result(answer: dict) -> tuple[str, float]:
    """
    Extract the selected choice and its confidence from a Laya choice answer.

    Laya choice answers return:
        {"choice": "billing", "confidence": 0.94, "probabilities": {"billing": 0.94, ...}}
    """
    choice = answer.get("choice", "unknown")
    confidence = float(answer.get("confidence", 0.0))
    return choice, confidence


def _extract_score_result(answer: dict) -> float:
    """
    Extract the expected level from a Laya score answer.

    Laya score answers return:
        {"expected_level": 2.35, "confidence": 0.81, "probabilities": [...], "legend": {...}}
    """
    return float(answer.get("expected_level", answer.get("value", answer.get("score", 0.0))))


def _extract_noul_result(answer: dict) -> float:
    """
    Extract the probability from a Laya noul (binary judgment) answer.

    Laya noul answers return:
        {"probability": 0.875, "confidence": 0.875}
    """
    return float(answer.get("probability", answer.get("value", 0.0)))


# ---------------------------------------------------------------------------
# Main pre-screen function
# ---------------------------------------------------------------------------
def run_laya_prescreen(
    *,
    email_subject: str,
    email_body_text: str,
    from_address: Optional[str] = None,
    model_override: Optional[str] = None,
    benign_confidence_threshold: float = 0.85,
    skip_ai_on_benign: bool = True,
) -> LayaPrescreenResult:
    """
    Run the Laya pre-screening pass on an email's text content.

    Returns a LayaPrescreenResult with typed decisions and routing metadata.
    On any failure, returns a result with status="error" so the pipeline
    can continue without interruption.

    Parameters
    ----------
    email_subject : str
        The email subject line.
    email_body_text : str
        The plaintext body of the email.
    from_address : str, optional
        The sender's email address (included in state for context).
    model_override : str, optional
        Force a specific Laya model checkpoint ("english", "multilingual",
        "typed-decisions").  None = auto-routing.
    benign_confidence_threshold : float
        Minimum confidence to consider a "benign" classification trustworthy
        enough to recommend skipping the AI Reasoner.
    skip_ai_on_benign : bool
        Whether to recommend skipping the AI Reasoner when Laya classifies
        the email as benign with high confidence.
    """
    router = _get_router()
    if router is None:
        return LayaPrescreenResult(
            status="error",
            error="Laya Router unavailable (initialization failed)",
        )

    # Build state dict from email content
    state: Dict[str, str] = {
        "subject": email_subject or "",
        "body": email_body_text or "",
    }
    if from_address:
        state["from"] = from_address

    try:
        t0 = time.perf_counter()

        # Call Laya Router with optional model override
        predict_kwargs: Dict[str, Any] = {}
        if model_override:
            predict_kwargs["model"] = model_override

        raw_result = router.predict(state, LAYA_QUESTIONS, **predict_kwargs)

        latency_ms = (time.perf_counter() - t0) * 1000.0
        answers = raw_result.get("answers", {})
        routing = raw_result.get("routing", {})

        # Extract typed answers
        tc_choice, tc_conf = _extract_choice_result(answers.get("threat_category", {}))
        urgency = _extract_score_result(answers.get("urgency", {}))
        se_prob = _extract_noul_result(answers.get("social_engineering", {}))
        fr_prob = _extract_noul_result(answers.get("financial_request", {}))
        ch_prob = _extract_noul_result(answers.get("credential_harvesting", {}))
        ei_prob = _extract_noul_result(answers.get("executive_impersonation", {}))

        model_used = routing.get("model", "unknown")

        # Determine if email is likely benign
        is_likely_benign = (tc_choice == "benign" and tc_conf >= benign_confidence_threshold)

        # Recommend AI skip only if configured AND benign with high confidence
        # AND no individual threat signals are elevated
        threat_signal_max = max(se_prob, fr_prob, ch_prob, ei_prob)
        skip_ai = (
            skip_ai_on_benign
            and is_likely_benign
            and threat_signal_max < 0.3
            and urgency < 0.5
        )

        result = LayaPrescreenResult(
            threat_category=tc_choice,
            threat_category_confidence=tc_conf,
            urgency_level=urgency,
            social_engineering_probability=se_prob,
            financial_request_probability=fr_prob,
            credential_harvesting_probability=ch_prob,
            executive_impersonation_probability=ei_prob,
            model_used=model_used,
            latency_ms=latency_ms,
            status="success",
            is_likely_benign=is_likely_benign,
            skip_ai_recommended=skip_ai,
        )

        logger.info(
            f"Laya pre-screen completed in {latency_ms:.1f}ms: "
            f"category={tc_choice} (conf={tc_conf:.2f}), "
            f"urgency={urgency:.2f}, model={model_used}, "
            f"skip_ai={skip_ai}"
        )
        return result

    except Exception as exc:
        logger.warning(f"Laya pre-screen failed (pipeline continues): {exc}")
        return LayaPrescreenResult(
            status="error",
            error=str(exc),
        )
