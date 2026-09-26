"""
Trusted Receiver Configuration - v1
=====================================

Owned by: Email Forensics module (Person 3).

Purpose: defines the SET of receiving infrastructure patterns that the
routing analyzer is permitted to treat as an independently-trusted
boundary when walking the Received chain from newest to oldest.

Design intent (per project spec):
  * Start deliberately small. Only well-documented Gmail and Microsoft
    365 receiving patterns are included in v1.
  * Do NOT loosen this list to make a specific test/fixture pass. If a
    fixture requires a pattern not here, either the pattern is added
    with a documented justification, or the fixture is accepted as
    correctly reporting an indeterminate/untrusted result.
  * This is a versioned artifact. Bump TRUSTED_RECEIVERS_VERSION on any
    change, and keep old versions loadable so historical investigations
    can be re-explained against the ruleset that was active when they
    ran (see "preserve history" project rule).

Matching model:
  Each entry is a (label, matcher) pair. A Received header's "by" claim
  is checked against `by_hostname_suffixes`; matching means the RECEIVING
  side of that hop is operated by the named trusted provider. This says
  nothing about the truthfulness of the "from" claim in the same hop -
  that is exactly why Hop-0 stops at the boundary rather than trusting
  the content of an untrusted hop's own "from" claim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

TRUSTED_RECEIVERS_VERSION = "v1"

# Gmail's final internal delivery hop (LMTP handoff into mail storage) is
# documented to record 'by' as an internal per-request token that looks
# like a bare IPv6-ish hextet string (e.g. "2002:a05:6902:100a:b0:d0a:...")
# rather than a hostname. This is a well-documented, stable Gmail pattern
# (not an inference from any single fixture), so it is recognized
# explicitly and narrowly here - it must only match tokens that are
# EXCLUSIVELY hex/colon characters, so it cannot be satisfied by an
# arbitrary attacker-chosen string.
_GMAIL_INTERNAL_DELIVERY_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){2,7}$")


@dataclass(frozen=True)
class TrustedReceiverPattern:
    label: str
    provider: str
    by_hostname_suffixes: tuple[str, ...] = field(default_factory=tuple)
    by_token_regex: "re.Pattern | None" = None
    notes: str = ""


TRUSTED_RECEIVER_PATTERNS: tuple[TrustedReceiverPattern, ...] = (
    TrustedReceiverPattern(
        label="gmail_mx",
        provider="google",
        by_hostname_suffixes=(
            "mx.google.com",
            "gmail.com",
            "google.com",
        ),
        notes=(
            "Google-operated inbound MX / internal relay hostnames as "
            "documented in Gmail's published Received header format. "
            "Internal Google relay-to-relay hops within this suffix set "
            "are treated as trusted boundary."
        ),
    ),
    TrustedReceiverPattern(
        label="gmail_internal_delivery_token",
        provider="google",
        by_token_regex=_GMAIL_INTERNAL_DELIVERY_TOKEN_RE,
        notes=(
            "Gmail's final internal delivery (LMTP-style) hop records 'by' "
            "as a bare hextet token identifying internal storage "
            "infrastructure, rather than a hostname. This is a documented, "
            "stable Gmail pattern; the regex only matches strings composed "
            "entirely of hex digits and colons, so it cannot be satisfied "
            "by an arbitrary or adversarial hostname."
        ),
    ),
    TrustedReceiverPattern(
        label="microsoft365_mx",
        provider="microsoft",
        by_hostname_suffixes=(
            "protection.outlook.com",
            "prod.outlook.com",
            "outlook.com",
        ),
        notes=(
            "Microsoft 365 / EOP (Exchange Online Protection) documented "
            "inbound and internal relay hostnames."
        ),
    ),
)


def by_claim_matches_trusted(by_claim: str | None) -> TrustedReceiverPattern | None:
    """
    Returns the matching TrustedReceiverPattern if the given 'by' claim
    hostname ends with one of the trusted suffixes, else None.

    This performs a conservative suffix match on the hostname token only
    (not the full claim string), to avoid false-positive matches on
    substrings appearing elsewhere in a malformed or adversarial claim.
    """
    if not by_claim:
        return None
    # by_claim may include extra tokens (e.g. "mx.google.com with ESMTPS id ...");
    # take the first whitespace-delimited token as the hostname candidate.
    hostname_candidate = by_claim.strip().split()[0].strip("()[]").lower()
    for pattern in TRUSTED_RECEIVER_PATTERNS:
        if pattern.by_token_regex is not None and pattern.by_token_regex.match(hostname_candidate):
            return pattern
        for suffix in pattern.by_hostname_suffixes:
            if hostname_candidate == suffix or hostname_candidate.endswith("." + suffix):
                return pattern
    return None


def hostname_trust_family(hostname: str | None) -> str | None:
    """
    Returns the trusted-provider label a given hostname/token belongs to
    (e.g. 'google', 'microsoft'), or None if it doesn't match any
    configured trusted pattern. Used by the routing analyzer to decide
    whether two adjacent hostnames within a trusted chain are merely
    different-but-consistent nodes of the SAME provider's infrastructure
    (common and expected in cloud mail systems) versus genuinely
    different, unrelated infrastructure.
    """
    match = by_claim_matches_trusted(hostname)
    return match.provider if match else None
