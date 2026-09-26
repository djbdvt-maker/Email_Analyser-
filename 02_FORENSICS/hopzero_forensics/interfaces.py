"""
HopZero Forensic Analysis Interface (typed contracts)
======================================================

This module defines the shared, typed data contracts that flow between the
forensics engine (this module) and the rest of the HopZero pipeline
(Score Engine, backend/orchestration, UI).

CRITICAL RULES (see project spec):
  * CanonicalEmail is PURELY DESCRIPTIVE. It must never contain a score,
    severity, verdict, "malicious" flag, or any LLM-derived conclusion.
  * Analyzers must not invent qualification codes; `qualification_code`
    values must come from the locked v1 vocabulary
    (see qualification_vocab.py).
  * Analyzers must not assign final severity or add points. `strength`
    is a registered enum value from the vocabulary, not a numeric score.
  * Missing signals are represented as UNAVAILABLE, never as "absent"
    (clean) and never silently dropped.
  * `analysis_run_id` is NOT generated here. Backend/orchestration owns
    the AnalysisRun identity and associates it with this output after
    the fact. This module's outputs are run-agnostic.

This file is intentionally dependency-light (stdlib + dataclasses/typing
only) so it can be reviewed and frozen quickly by the rest of the team.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Signal availability
# ---------------------------------------------------------------------------

class SignalState(str, Enum):
    """
    Tri-state used throughout facts/candidates to distinguish:
      PRESENT     -> the signal was observed and has a concrete value
      ABSENT      -> the signal was actively checked for and confirmed
                     not to exist (e.g. no DKIM-Signature header at all)
      UNAVAILABLE -> the signal could not be determined (parse failure,
                     unsupported encoding, missing external data, etc.)

    UNAVAILABLE must NEVER be interpreted as a negative/clean finding
    downstream. This is a hard project rule.
    """
    PRESENT = "present"
    ABSENT = "absent"
    UNAVAILABLE = "unavailable"


# ---------------------------------------------------------------------------
# CanonicalEmail substructures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RawHeader:
    """A single header as it appeared in the original message, order-preserved."""
    name: str                # normalized lower-case header name, e.g. "received"
    value: str                # decoded value (RFC 2047 decoded where applicable)
    raw_line: str              # the original, undecoded header line(s), verbatim
    sequence_index: int         # 0-based position in the original header block


@dataclass(frozen=True)
class EmailAddress:
    """A single parsed address; raw_value is preserved verbatim for forensic replay."""
    display_name: Optional[str]
    address: Optional[str]      # local@domain, lower-cased domain; None if unparsable
    raw_value: str               # the original header value this was extracted from
    parse_state: SignalState


@dataclass(frozen=True)
class ReceivedHopRaw:
    """
    One 'Received:' header, minimally structured but NOT yet trust-evaluated.
    Trust evaluation / Hop-0 determination is done by the routing analyzer,
    not here. This is purely a structural extraction.
    """
    sequence_index: int          # position in header block (0 = topmost/newest)
    raw_line: str
    from_claim: Optional[str]     # the "from" token(s) as claimed by the relay, unverified
    by_claim: Optional[str]       # the "by" token, unverified
    with_claim: Optional[str]
    for_claim: Optional[str]
    observed_ip: Optional[str]     # IP literal extracted from the from-clause, if any
    timestamp_raw: Optional[str]    # the trailing date-time, unparsed string
    timestamp_parsed: Optional[datetime]
    parse_state: SignalState
    malformed_reason: Optional[str]  # populated only when parse_state != PRESENT


@dataclass(frozen=True)
class ExtractedLink:
    """A single hyperlink found in the (sanitized) HTML or plaintext body."""
    link_id: str
    href: str                      # the literal href/target, as written
    display_text: Optional[str]      # visible anchor text, if any
    source: str                     # "html" | "plaintext"
    context_snippet: Optional[str]     # short surrounding text for evidence display


@dataclass(frozen=True)
class ExtractedAttachment:
    """Structural facts about one attachment/MIME part. No execution, no sandboxing."""
    attachment_id: str
    filename: Optional[str]
    declared_mime_type: Optional[str]
    size_bytes: Optional[int]
    sha256: Optional[str]
    content_disposition: Optional[str]
    is_inline: bool
    within_archive: bool             # true if this is a member of an extracted archive
    parse_state: SignalState


@dataclass(frozen=True)
class EmailBody:
    text_plain: Optional[str]
    html_sanitized: Optional[str]     # HTML with scripts/active content stripped for safe display
    html_available: bool               # True if an HTML part existed at all (independent of sanitization)
    links: list[ExtractedLink] = field(default_factory=list)


# ---------------------------------------------------------------------------
# CanonicalEmail
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CanonicalEmail:
    """
    The single normalized representation that ALL downstream analyzers,
    the semantic AI step, and the Score Engine consume instead of
    re-parsing the raw .eml.

    Purely descriptive. No score/verdict/maliciousness/LLM fields here.

    IDENTITY - READ BEFORE USING `id` OR `artifact_id`:
      * `artifact_id` is the STABLE identity of the underlying raw email
        artifact. It is assigned and owned by backend persistence, not
        generated here - this module only accepts and carries whatever
        artifact_id it is given. Two parses of the exact same stored
        artifact (e.g. a re-run) MUST carry the same artifact_id.
      * `id` is NOT a stable artifact identity. It identifies THIS
        particular parse instance/invocation and is freshly generated
        per call to parse_eml() unless the caller explicitly supplies
        one. Re-parsing the same artifact_id twice will, by default,
        produce two CanonicalEmail objects with two different `id`
        values. Do not use `id` as a dedup key, a cache key, or a
        cross-run correlation key for "the same email" - use
        `artifact_id` for that. `id` exists only to give this specific
        in-memory/serialized instance a handle (e.g. for logging a
        specific parse attempt), not to identify the email itself.
      * There is deliberately only ONE backend-relevant identity concept
        here (`artifact_id`). `id` is a parse-instance handle, not a
        competing identity.
    """
    id: str                          # parse-instance identifier (see docstring above) - NOT the artifact identity
    artifact_id: str                  # STABLE identity of the underlying raw .eml, owned by backend persistence
    message_id: Optional[str]
    parsed_at: datetime

    headers: list[RawHeader]

    # Address fields - each is a list because header can legally repeat / contain multiple addrs
    from_addresses: list[EmailAddress]
    reply_to_addresses: list[EmailAddress]
    return_path: Optional[EmailAddress]
    to_addresses: list[EmailAddress]
    cc_addresses: list[EmailAddress]

    received_chain_raw: list[ReceivedHopRaw]   # ordered as they appeared, top (newest) first

    body: EmailBody
    attachments: list[ExtractedAttachment]

    subject: Optional[str]
    date_raw: Optional[str]
    date_parsed: Optional[datetime]

    # Parsing-level integrity signals - NOT security findings, just structural facts
    parse_warnings: list[str] = field(default_factory=list)
    is_truncated: bool = False


# ---------------------------------------------------------------------------
# Analyzer output contract: Facts + FindingCandidates
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Fact:
    """
    A deterministic, atomic observation produced by an analyzer.
    Facts are the evidentiary basis that FindingCandidates cite via
    `supporting_fact_ids`. Facts themselves carry no scoring weight.
    """
    fact_id: str
    category: str                 # e.g. "routing", "authentication", "domain"
    key: str                       # e.g. "hop0_candidate_ip", "spf_result"
    state: SignalState
    value: Optional[str]            # stringified value; None when state != PRESENT
    produced_by: str                 # analyzer name/version, e.g. "routing_analyzer@1.0"
    detail: Optional[str] = None       # free-text explanation, safe for evidence display


@dataclass(frozen=True)
class FindingCandidate:
    """
    Structure mandated by the shared spec. Deterministic analyzers may set
    `strength` directly from the registered vocabulary value for the given
    qualification_code; they must never invent a new code or strength scale.
    """
    category: str
    qualification_code: str
    qualification_version: str
    strength: str                     # registered enum/string from the vocabulary, not a number
    normalized_subject: Optional[str]     # e.g. the domain, address, or IP the finding is about
    normalized_target: Optional[str]       # e.g. the impersonated brand/domain, if applicable
    claim_signature: str                    # stable dedup key: category+code+subject+target
    supporting_fact_ids: list[str]
    supporting_text: Optional[str]
    produced_by: str


@dataclass(frozen=True)
class AnalyzerOutput:
    """Every analyzer returns exactly this shape."""
    analyzer_name: str
    analyzer_version: str
    facts: list[Fact]
    candidates: list[FindingCandidate]


# ---------------------------------------------------------------------------
# Evidence Normalizer contracts
# ---------------------------------------------------------------------------
#
# These types are produced by the Evidence Normalizer, which runs AFTER
# parsing/CanonicalEmail and BEFORE semantic AI / deterministic semantic
# predicates. They are intentionally a SEPARATE structure from
# CanonicalEmail - normalization never mutates CanonicalEmail, and
# CanonicalEmail is never treated as if it were normalized.
#
# Like CanonicalEmail, this is purely mechanical/descriptive output: no
# score, severity, verdict, or LLM conclusion may ever be added here, and
# no qualification code is invented or referenced here - the normalizer
# does not produce Facts or FindingCandidates.

@dataclass(frozen=True)
class NormalizationEvent:
    """
    A single deterministic, mechanical transformation applied while
    deriving normalized text from original text. This is never a
    semantic or security judgment - it only records "this span of
    original text became this span of normalized text, and here is
    which mechanical rule most plausibly explains it."

    `transformation` is a best-effort classification label (see
    evidence_normalizer.py for how it's derived), not a guarantee that
    exactly one rule produced the change - NFKC, zero-width removal, and
    whitespace normalization can occasionally interact within the same
    changed span.
    """
    transformation: str            # e.g. "zero_width_removed" | "unicode_whitespace_normalized" | "nfkc_compatibility_normalization"
    position: int                    # start index into ORIGINAL text where this change begins
    original_span: str
    replacement_span: str | None       # None if the span was removed entirely
    codepoints: str                     # comma-separated "U+XXXX" codepoints of original_span
    detail: str | None = None


@dataclass(frozen=True)
class NormalizedField:
    """
    One normalized text surface, fully traceable back to its exact
    source text and source location within CanonicalEmail.
    """
    field_path: str                # e.g. "subject", "body.text_plain", "from_addresses[0].display_name"
    original_text: str              # verbatim, unmodified - copied here for traceability convenience
    normalized_text: str
    policy_version: str
    events: list[NormalizationEvent]
    unchanged: bool                  # True iff normalized_text == original_text (redundant with events==[] but explicit)


@dataclass(frozen=True)
class NormalizedEvidence:
    """
    The separate, analysis-facing canonical representation. Consumed by
    semantic AI and deterministic semantic predicates INSTEAD OF raw
    CanonicalEmail text fields, so that obfuscation tricks (zero-width
    insertion, unusual whitespace, full-width character substitution)
    don't defeat keyword/pattern matching - while the original,
    unmodified text and the raw .eml artifact remain fully intact and
    traceable via `source_canonical_email_id` / `source_artifact_id`.
    """
    source_canonical_email_id: str    # CanonicalEmail.id this was derived from (a parse-instance handle, not an artifact identity)
    source_artifact_id: str             # passthrough of CanonicalEmail.artifact_id, for stable correlation
    policy_version: str
    produced_by: str
    fields: list[NormalizedField]
