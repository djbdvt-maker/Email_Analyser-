"""
Evidence Normalizer
=====================

Runs AFTER parsing/CanonicalEmail and BEFORE semantic AI / deterministic
semantic predicates. Produces `NormalizedEvidence` - a SEPARATE
analysis-facing representation - without ever mutating CanonicalEmail or
touching the underlying raw .eml artifact.

Purpose: obfuscation techniques like zero-width character insertion,
unusual Unicode whitespace, and full-width/compatibility character
substitution can defeat naive keyword/pattern matching while looking
identical (or nearly identical) to a human. This module deterministically
normalizes text surfaces so downstream semantic predicates and the LLM
see a canonical form, while the original text and raw artifact remain
fully intact and every change is traceable back to the exact original
span that produced it.

This is MECHANICAL normalization only:
  * No semantic interpretation, no scoring, no verdicts.
  * No qualification codes - this module does not produce Facts or
    FindingCandidates at all.
  * No LLM calls, no network calls - stdlib `unicodedata` + `difflib`
    only.
  * No confusable/homoglyph folding (see NORMALIZATION_DESIGN.md and
    config/normalization_policy_v1.py for the detailed reasoning on why
    this is deliberately excluded from this layer).

Pipeline (fixed order, deterministic):
  1. Remove zero-width / invisible characters (explicit codepoint list).
  2. Replace unusual Unicode whitespace with canonical ASCII space/newline
     (explicit codepoint map).
  3. Apply NFKC (Unicode compatibility normalization) to the result -
     this is what folds full-width/half-width forms, ligatures,
     superscripts, etc. into their canonical compatibility form.

A diff between the ORIGINAL text and the FINAL normalized text is then
computed (via `difflib.SequenceMatcher`) to produce an explicit,
traceable list of `NormalizationEvent`s, each best-effort classified by
which rule most plausibly explains it.
"""

from __future__ import annotations

import difflib
import unicodedata

from .config.normalization_policy_v1 import (
    NORMALIZATION_POLICY_VERSION,
    UNICODE_WHITESPACE_MAP,
    ZERO_WIDTH_AND_INVISIBLE_CODEPOINTS,
)
from .interfaces import (
    CanonicalEmail,
    NormalizationEvent,
    NormalizedEvidence,
    NormalizedField,
)

MODULE_NAME = "evidence_normalizer"
MODULE_VERSION = "1.0"


def _codepoints_of(span: str) -> str:
    return ",".join(f"U+{ord(ch):04X}" for ch in span)


def _classify_span(original_span: str) -> str:
    """
    Best-effort classification of which mechanical rule most plausibly
    explains a changed span. This is diagnostic/auditability labeling,
    not a claim that exactly one rule fired - NFKC, zero-width removal,
    and whitespace normalization can occasionally interact within the
    same changed span (e.g. a zero-width char sitting directly beside a
    full-width character that also changes). In that mixed case this
    falls through to the general NFKC label, which is still an accurate
    (if less specific) description of "this span differs due to
    normalization."
    """
    if original_span and all(ch in ZERO_WIDTH_AND_INVISIBLE_CODEPOINTS for ch in original_span):
        return "zero_width_removed"
    if original_span and all(ch in UNICODE_WHITESPACE_MAP for ch in original_span):
        return "unicode_whitespace_normalized"
    return "nfkc_compatibility_normalization"


def normalize_text(original_text: str, field_path: str) -> NormalizedField:
    """
    Applies the fixed, versioned normalization pipeline to a single text
    surface and returns a fully traceable NormalizedField.

    Never mutates or discards the original text - it is preserved
    verbatim on the returned object regardless of what normalization
    produces.
    """
    # Step 1: remove zero-width / invisible characters.
    stage1 = "".join(ch for ch in original_text if ch not in ZERO_WIDTH_AND_INVISIBLE_CODEPOINTS)

    # Step 2: normalize unusual Unicode whitespace to canonical ASCII forms.
    stage2 = "".join(UNICODE_WHITESPACE_MAP.get(ch, ch) for ch in stage1)

    # Step 3: NFKC compatibility normalization (folds full-width/half-width
    # forms, ligatures, compatibility variants, etc.).
    normalized_text = unicodedata.normalize("NFKC", stage2)

    if normalized_text == original_text:
        return NormalizedField(
            field_path=field_path,
            original_text=original_text,
            normalized_text=normalized_text,
            policy_version=NORMALIZATION_POLICY_VERSION,
            events=[],
            unchanged=True,
        )

    events: list[NormalizationEvent] = []
    matcher = difflib.SequenceMatcher(None, original_text, normalized_text, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        original_span = original_text[i1:i2]
        replacement_span = normalized_text[j1:j2] or None
        events.append(
            NormalizationEvent(
                transformation=_classify_span(original_span),
                position=i1,
                original_span=original_span,
                replacement_span=replacement_span,
                codepoints=_codepoints_of(original_span),
                detail=(
                    f"original[{i1}:{i2}]={original_span!r} -> "
                    f"normalized[{j1}:{j2}]={(replacement_span or '')!r}"
                ),
            )
        )

    return NormalizedField(
        field_path=field_path,
        original_text=original_text,
        normalized_text=normalized_text,
        policy_version=NORMALIZATION_POLICY_VERSION,
        events=events,
        unchanged=False,
    )


def normalize_email(email: CanonicalEmail) -> NormalizedEvidence:
    """
    Produces the full NormalizedEvidence for a CanonicalEmail.

    Scope (v1) - the analysis-facing, human/AI-readable text surfaces:
      * subject
      * body.text_plain
      * display_name of every parsed address (from/reply-to/return-path/to/cc)
      * attachment filenames

    Deliberately OUT OF SCOPE (see NORMALIZATION_DESIGN.md):
      * Raw HTML body markup (body.html_sanitized) - normalizing text
        embedded in HTML tags risks corrupting tag/attribute syntax;
        this would need a dedicated text-extraction-from-HTML step,
        which does not exist yet.
      * Link hrefs / URLs - domain-specific IDN/punycode handling
        belongs to the (not yet implemented) Domain/Links analyzers,
        not to blind mechanical text normalization.
      * Raw header values in general (only the specific address
        display-name and filename surfaces above are in scope for v1).

    Only fields that actually have text are included - absent fields are
    simply omitted, not fabricated as empty NormalizedFields. (Signal
    availability itself is CanonicalEmail's/analyzers' concern via
    SignalState, not this module's.)
    """
    fields: list[NormalizedField] = []

    if email.subject is not None:
        fields.append(normalize_text(email.subject, "subject"))

    if email.body.text_plain is not None:
        fields.append(normalize_text(email.body.text_plain, "body.text_plain"))

    address_groups = (
        ("from_addresses", email.from_addresses),
        ("reply_to_addresses", email.reply_to_addresses),
        ("to_addresses", email.to_addresses),
        ("cc_addresses", email.cc_addresses),
    )
    for group_name, addresses in address_groups:
        for i, addr in enumerate(addresses):
            if addr.display_name:
                fields.append(normalize_text(addr.display_name, f"{group_name}[{i}].display_name"))

    if email.return_path is not None and email.return_path.display_name:
        fields.append(normalize_text(email.return_path.display_name, "return_path.display_name"))

    for i, att in enumerate(email.attachments):
        if att.filename:
            fields.append(normalize_text(att.filename, f"attachments[{i}].filename"))

    return NormalizedEvidence(
        source_canonical_email_id=email.id,
        source_artifact_id=email.artifact_id,
        policy_version=NORMALIZATION_POLICY_VERSION,
        produced_by=f"{MODULE_NAME}@{MODULE_VERSION}",
        fields=fields,
    )
