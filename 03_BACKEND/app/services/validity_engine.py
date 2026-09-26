"""
Deterministic validity engine (P1 #5).
======================================

The locked design enforces:
A validity requirement may inspect ONLY:
- candidate supporting_text
- bounded structural context (the local sentence/clause window)
- explicitly allow-listed deterministic_context paths
- versioned pattern/reference sets

It MUST NOT inspect:
- other Findings
- other candidates
- other categories
- history
- database state
- network state
- wall clock
- randomness
- model confidence
- model suggested strength
- another LLM

H2 validity protects against:
- H2a context stripping (e.g., extracting an action out of testing/training context)
- H2b semantic/claim misclassification

Closed predicate DSL:
- contains_pattern
- matches_structural_form
- fact_equals
- fact_in_set
- absence_of_pattern
- span_relation
Operators:
- AND
- OR
- NOT

NO eval(), NO exec(). Safe dictionary and function dispatch only.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Union

VALIDITY_ENGINE_VERSION = "vr-v1"

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")


class ValidityResult:
    def __init__(self, is_valid: bool, reason: str = ""):
        self.is_valid = is_valid
        self.reason = reason

    def __bool__(self) -> bool:
        return self.is_valid


def _find_local_window(source_text: str, supporting_text: str) -> str:
    """
    Returns the sentence (or line, for sentence-less text) containing
    the first occurrence of supporting_text within source_text. This
    is deliberately local -- it is NOT the whole document.
    """
    if not source_text or not supporting_text:
        return ""
    idx = source_text.find(supporting_text)
    if idx == -1:
        return ""
    sentences = _SENTENCE_SPLIT_RE.split(source_text)
    offset = 0
    for sentence in sentences:
        start = source_text.find(sentence, offset)
        end = start + len(sentence)
        if start <= idx < end:
            return sentence
        offset = end
    return source_text  # fallback: whole text, if segmentation failed


def check_grounding(source_text: str, supporting_text: str) -> ValidityResult:
    """
    Validates that supporting_text is an exact, contiguous substring of source_text.
    """
    if not supporting_text:
        return ValidityResult(False, "supporting_text is empty")
    if supporting_text not in source_text:
        return ValidityResult(False, "supporting_text is not a substring of the source text (not grounded)")
    return ValidityResult(True)


def check_h2_semantic_validity(
    source_text: str,
    supporting_text: str,
    disqualifier_phrases: Sequence[str],
) -> ValidityResult:
    """
    The H2 hard gate: grounding alone is insufficient. If the local
    sentence containing the grounded span also contains a disqualifier
    phrase (hypothetical/training/simulated framing), the candidate is
    semantically invalid -- REJECTED, never downgraded to Weak/Moderate.
    """
    window = _find_local_window(source_text, supporting_text)
    window_lower = window.lower()
    for phrase in disqualifier_phrases:
        if phrase.lower() in window_lower:
            return ValidityResult(
                False,
                f"local context contains disqualifying framing ('{phrase}'); "
                f"the claim is not actually being made, only discussed/tested",
            )
    return ValidityResult(True)


# ------------------------------------------------------------------
# Primitive Predicate Implementations (Closed DSL)
# ------------------------------------------------------------------

_PAYMENT_ACTION_VERBS = ("wire", "transfer", "send payment", "process the payment", "pay ", "remit")
_MONETARY_OR_ACCOUNT_RE = re.compile(
    r"(\$\s?\d[\d,]*(\.\d+)?|\b\d{1,3}(,\d{3})*(\.\d+)?\s?(usd|dollars|eur|gbp)\b|"
    r"\baccount\s*(number|no\.?|#)?\s*[:#]?\s*\d{4,}\b|\brouting\s*(number|no\.?)?\s*[:#]?\s*\d{4,}\b)",
    re.IGNORECASE,
)


def pred_contains_pattern(target_text: str, pattern: str) -> bool:
    """Checks if a literal string or regex pattern exists in target_text."""
    if not target_text or not pattern:
        return False
    try:
        return bool(re.search(pattern, target_text, re.IGNORECASE))
    except re.error:
        return pattern.lower() in target_text.lower()


def pred_absence_of_pattern(target_text: str, pattern: str) -> bool:
    """Checks if a pattern is absent from target_text."""
    return not pred_contains_pattern(target_text, pattern)


def pred_matches_structural_form(target_text: str, form_type: str) -> bool:
    """Matches structural forms such as monetary amounts, email addresses, or URLs."""
    if form_type == "monetary_amount":
        return bool(_MONETARY_OR_ACCOUNT_RE.search(target_text))
    elif form_type == "payment_action":
        lower = target_text.lower()
        return any(v in lower for v in _PAYMENT_ACTION_VERBS)
    elif form_type == "email_address":
        return bool(re.search(r"[\w\.-]+@[\w\.-]+\.\w+", target_text))
    elif form_type == "url":
        return bool(re.search(r"https?://\S+", target_text))
    return False


def pred_fact_equals(
    fact_path: str,
    expected_value: Any,
    deterministic_context: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Safely checks an allow-listed deterministic context path against an expected value.
    Paths are strictly constrained to allow-listed keys (e.g., 'auth.spf', 'headers.from_domain').
    """
    if not deterministic_context:
        return False
    # Only allow safe dot-separated path lookups
    parts = fact_path.split(".")
    curr: Any = deterministic_context
    for p in parts:
        if isinstance(curr, dict) and p in curr:
            curr = curr[p]
        else:
            return False
    return str(curr).lower() == str(expected_value).lower()


def pred_fact_in_set(
    fact_path: str,
    allowed_set: Sequence[Any],
    deterministic_context: Optional[Dict[str, Any]] = None,
) -> bool:
    """Checks if an allow-listed deterministic context value is within allowed_set."""
    if not deterministic_context:
        return False
    parts = fact_path.split(".")
    curr: Any = deterministic_context
    for p in parts:
        if isinstance(curr, dict) and p in curr:
            curr = curr[p]
        else:
            return False
    allowed_lowers = {str(x).lower() for x in allowed_set}
    return str(curr).lower() in allowed_lowers


def pred_span_relation(
    span_a: str,
    span_b: str,
    relation: str,
    source_text: str = "",
) -> bool:
    """
    Evaluates geometric relation between two grounded spans in the source text:
    'precedes', 'follows', 'within_window', 'disjoint'.
    """
    if not source_text or not span_a or not span_b:
        return False
    pos_a = source_text.find(span_a)
    pos_b = source_text.find(span_b)
    if pos_a == -1 or pos_b == -1:
        return False

    if relation == "precedes":
        return pos_a + len(span_a) <= pos_b
    elif relation == "follows":
        return pos_b + len(span_b) <= pos_a
    elif relation == "within_window":
        return abs(pos_a - pos_b) <= 200  # Within 200 characters
    elif relation == "disjoint":
        return (pos_a + len(span_a) <= pos_b) or (pos_b + len(span_b) <= pos_a)
    return False


# ------------------------------------------------------------------
# Safe Composite Predicate Evaluator (AND / OR / NOT)
# ------------------------------------------------------------------

def evaluate_dsl_expression(
    expr: Dict[str, Any],
    *,
    supporting_text: str,
    local_window: str,
    deterministic_context: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Evaluates a structured predicate dictionary using locked operators (AND, OR, NOT).
    NO eval() or exec() is used.
    """
    if not isinstance(expr, dict):
        return False

    op = expr.get("op", "").upper()

    if op == "AND":
        args = expr.get("args", [])
        return all(evaluate_dsl_expression(a, supporting_text=supporting_text, local_window=local_window, deterministic_context=deterministic_context) for a in args)

    if op == "OR":
        args = expr.get("args", [])
        return any(evaluate_dsl_expression(a, supporting_text=supporting_text, local_window=local_window, deterministic_context=deterministic_context) for a in args)

    if op == "NOT":
        arg = expr.get("arg", {})
        return not evaluate_dsl_expression(arg, supporting_text=supporting_text, local_window=local_window, deterministic_context=deterministic_context)

    # Leaf predicates
    pred = expr.get("predicate")
    target = local_window if expr.get("target") == "window" else supporting_text

    if pred == "contains_pattern":
        return pred_contains_pattern(target, expr.get("pattern", ""))
    elif pred == "absence_of_pattern":
        return pred_absence_of_pattern(target, expr.get("pattern", ""))
    elif pred == "matches_structural_form":
        return pred_matches_structural_form(target, expr.get("form_type", ""))
    elif pred == "fact_equals":
        return pred_fact_equals(expr.get("fact_path", ""), expr.get("expected_value"), deterministic_context)
    elif pred == "fact_in_set":
        return pred_fact_in_set(expr.get("fact_path", ""), expr.get("allowed_set", []), deterministic_context)
    elif pred == "span_relation":
        return pred_span_relation(expr.get("span_a", ""), expr.get("span_b", ""), expr.get("relation", ""), local_window)

    return False


# ------------------------------------------------------------------
# Legacy / Named Predicates for Registry Strength Rules
# ------------------------------------------------------------------

def predicate_explicit_payment_action(window: str, supporting_text: str) -> bool:
    text = (window or supporting_text).lower()
    return any(verb in text for verb in _PAYMENT_ACTION_VERBS)


def predicate_monetary_amount_or_account_present(window: str, supporting_text: str) -> bool:
    text = window or supporting_text
    return bool(_MONETARY_OR_ACCOUNT_RE.search(text))


def predicate_display_name_mismatch_confirmed(window: str, supporting_text: str) -> bool:
    return False


_PREDICATES = {
    "explicit_payment_action": predicate_explicit_payment_action,
    "monetary_amount_or_account_present": predicate_monetary_amount_or_account_present,
    "display_name_mismatch_confirmed": predicate_display_name_mismatch_confirmed,
}


def evaluate_predicate(name: str, window: str, supporting_text: str) -> bool:
    fn = _PREDICATES.get(name)
    if fn is None:
        raise KeyError(f"Unknown strength predicate: {name}")
    return fn(window, supporting_text)


def get_local_window(source_text: str, supporting_text: str) -> str:
    return _find_local_window(source_text, supporting_text)
