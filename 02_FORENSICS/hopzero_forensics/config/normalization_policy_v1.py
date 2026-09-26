"""
Evidence Normalization Policy - v1
=====================================

Owned by: Email Forensics module (Person 3).

This defines WHICH mechanical, deterministic transformations the Evidence
Normalizer applies, as an explicit, versioned, curated policy - not a
dynamic lookup against a Unicode character database version that could
shift silently between environments.

Scope of this policy (v1):
  1. Zero-width / invisible character removal - an explicit, curated
     codepoint list (see ZERO_WIDTH_AND_INVISIBLE_CODEPOINTS below).
  2. Unusual Unicode whitespace normalization - an explicit mapping of
     non-standard space/line-separator codepoints to canonical ASCII
     space/newline (see UNICODE_WHITESPACE_MAP below).
  3. NFKC normalization (applied via Python's stdlib `unicodedata`,
     which is NOT reconfigurable via this file - it is applied as a
     final pass in evidence_normalizer.py).

Explicitly OUT OF SCOPE for this policy (see NORMALIZATION_DESIGN.md for
full reasoning):
  * Confusable/homoglyph "skeleton" folding (e.g. Cyrillic 'а' -> Latin
    'a') is NOT applied anywhere in this policy. It is not a general
    text-normalization operation - it is a narrow, domain-comparison-
    specific technique that belongs (if implemented at all) to the
    Domain analyzer, scoped strictly to comparing a candidate domain
    label against a protected-brand list. Applying it to arbitrary body
    text, subject lines, or display names would silently corrupt
    genuine multilingual content (Russian, Greek, Ukrainian, Serbian,
    etc. all use scripts with characters that are "confusable" with
    Latin letters) and would destroy the very mixed-script signal that
    downstream analyzers need to detect impersonation.
  * Case-folding / lowercasing of arbitrary text.
  * Stripping of combining diacritical marks (accents) - these are
    semantically meaningful in normal multilingual text.
  * Any transformation of URLs/hrefs - those are handled (if at all) by
    domain-specific IDN/punycode logic in the Domain/Links analyzers,
    never by blind text normalization.

Versioning: bump NORMALIZATION_POLICY_VERSION whenever this file's
codepoint sets or mappings change, and keep old versions available/
documented so a historical investigation can be re-explained against
the exact policy that was active when it ran.
"""

from __future__ import annotations

NORMALIZATION_POLICY_VERSION = "v1"


# ---------------------------------------------------------------------------
# Zero-width / invisible characters - removed entirely, each removal logged.
# ---------------------------------------------------------------------------
#
# This is a curated, explicit list rather than a dynamic Unicode General
# Category lookup (e.g. category "Cf" / "Format"), so that behavior is
# stable and independent of the Unicode Character Database version bundled
# with whatever Python runtime executes this code. Extend this list via an
# explicit version bump (v2, v3, ...) if gaps are found - do not silently
# widen it in place.

ZERO_WIDTH_AND_INVISIBLE_CODEPOINTS: frozenset[str] = frozenset(
    {
        "\u00ad",  # SOFT HYPHEN
        "\u034f",  # COMBINING GRAPHEME JOINER
        "\u061c",  # ARABIC LETTER MARK
        "\u115f",  # HANGUL CHOSEONG FILLER
        "\u1160",  # HANGUL JUNGSEONG FILLER
        "\u17b4",  # KHMER VOWEL INHERENT AQ
        "\u17b5",  # KHMER VOWEL INHERENT AA
        "\u180b",  # MONGOLIAN FREE VARIATION SELECTOR ONE
        "\u180c",  # MONGOLIAN FREE VARIATION SELECTOR TWO
        "\u180d",  # MONGOLIAN FREE VARIATION SELECTOR THREE
        "\u180e",  # MONGOLIAN VOWEL SEPARATOR
        "\u200b",  # ZERO WIDTH SPACE
        "\u200c",  # ZERO WIDTH NON-JOINER
        "\u200d",  # ZERO WIDTH JOINER
        "\u200e",  # LEFT-TO-RIGHT MARK
        "\u200f",  # RIGHT-TO-LEFT MARK
        "\u202a",  # LEFT-TO-RIGHT EMBEDDING
        "\u202b",  # RIGHT-TO-LEFT EMBEDDING
        "\u202c",  # POP DIRECTIONAL FORMATTING
        "\u202d",  # LEFT-TO-RIGHT OVERRIDE
        "\u202e",  # RIGHT-TO-LEFT OVERRIDE
        "\u2060",  # WORD JOINER
        "\u2061",  # FUNCTION APPLICATION
        "\u2062",  # INVISIBLE TIMES
        "\u2063",  # INVISIBLE SEPARATOR
        "\u2064",  # INVISIBLE PLUS
        "\u2066",  # LEFT-TO-RIGHT ISOLATE
        "\u2067",  # RIGHT-TO-LEFT ISOLATE
        "\u2068",  # FIRST STRONG ISOLATE
        "\u2069",  # POP DIRECTIONAL ISOLATE
        "\u3164",  # HANGUL FILLER
        "\ufeff",  # ZERO WIDTH NO-BREAK SPACE / BYTE ORDER MARK
        "\uffa0",  # HALFWIDTH HANGUL FILLER
    }
    | {chr(cp) for cp in range(0xFE00, 0xFE10)}  # VARIATION SELECTOR-1..16
)


# ---------------------------------------------------------------------------
# Unusual Unicode whitespace - normalized to a canonical ASCII replacement.
# ---------------------------------------------------------------------------
#
# Standard ASCII space (U+0020), tab (U+0009), CR (U+000D), and LF
# (U+000A) are left untouched - they are expected, unremarkable email
# whitespace. This map only covers non-ASCII / non-standard spacing and
# line-separator characters that could otherwise be used to visually
# mimic normal spacing while evading naive keyword/pattern matching.

UNICODE_WHITESPACE_MAP: dict[str, str] = {
    "\u00a0": " ",  # NO-BREAK SPACE
    "\u1680": " ",  # OGHAM SPACE MARK
    "\u2000": " ",  # EN QUAD
    "\u2001": " ",  # EM QUAD
    "\u2002": " ",  # EN SPACE
    "\u2003": " ",  # EM SPACE
    "\u2004": " ",  # THREE-PER-EM SPACE
    "\u2005": " ",  # FOUR-PER-EM SPACE
    "\u2006": " ",  # SIX-PER-EM SPACE
    "\u2007": " ",  # FIGURE SPACE
    "\u2008": " ",  # PUNCTUATION SPACE
    "\u2009": " ",  # THIN SPACE
    "\u200a": " ",  # HAIR SPACE
    "\u2028": "\n",  # LINE SEPARATOR
    "\u2029": "\n",  # PARAGRAPH SEPARATOR
    "\u202f": " ",  # NARROW NO-BREAK SPACE
    "\u205f": " ",  # MEDIUM MATHEMATICAL SPACE
    "\u3000": " ",  # IDEOGRAPHIC SPACE
}
