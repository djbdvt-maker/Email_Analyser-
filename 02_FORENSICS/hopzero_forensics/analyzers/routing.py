"""
Routing / Hop-0 Analyzer
=========================

Determines the CANDIDATE PROBABLE-ORIGIN IP by walking the Received chain
from a trusted receiving boundary toward older hops, and detects the three
validated CF-06 routing-fabrication conditions.

Hard rules enforced here:
  * The result is called "candidate probable-origin IP", never "attacker
    IP" or any language implying attribution.
  * Trust boundary walking STOPS at the first hop whose 'by' claim is not
    recognized by the v1 trusted-receiver configuration. It does not
    "look ahead" or make exceptions.
  * If there is no Received chain at all, origin is INDETERMINATE - this
    is represented as SignalState.UNAVAILABLE, not as a clean/negative
    result.
  * Only the three validated CF-06 conditions may be emitted as CF-06
    candidates. Generic malformedness (e.g. a single unparsable header)
    is recorded as a Fact but never auto-promoted to a CF-06 candidate.
  * This analyzer does not score, does not assign severity, and does not
    decide a verdict. It emits Facts + FindingCandidates only.
"""

from __future__ import annotations

from datetime import timedelta

from ..config.trusted_receivers_v1 import (
    TRUSTED_RECEIVERS_VERSION,
    by_claim_matches_trusted,
    hostname_trust_family,
)
from ..interfaces import (
    AnalyzerOutput,
    CanonicalEmail,
    Fact,
    FindingCandidate,
    ReceivedHopRaw,
    SignalState,
)
import os
import sys

# Ensure 01_REGISTRY is available on sys.path if not installed
try:
    from hopzero_registry.loader import load_registry
except ImportError:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    reg_path = os.path.join(repo_root, "01_REGISTRY")
    if reg_path not in sys.path:
        sys.path.insert(0, reg_path)
    from hopzero_registry.loader import load_registry

_REG_DATA = load_registry(version="v1", verify_hash=False)
_REG_QUALS = _REG_DATA.get("qualifications", {})

def _get_qual_meta(code: str) -> tuple[str, str]:
    if code in _REG_QUALS:
        return _REG_QUALS[code].category, _REG_QUALS[code].default_strength
    return "Routing", "Strong"

VOCABULARY_VERSION = "v1"

ANALYZER_NAME = "routing_analyzer"
ANALYZER_VERSION = "1.0"

# Bounded clock-skew tolerance for temporal-contradiction detection.
# Deliberately conservative/explicit rather than inferred.
TEMPORAL_TOLERANCE = timedelta(minutes=5)


def _fact(fid: str, category: str, key: str, state: SignalState, value, detail: str | None = None) -> Fact:
    return Fact(
        fact_id=fid,
        category=category,
        key=key,
        state=state,
        value=None if value is None else str(value),
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
        detail=detail,
    )


def _establish_trust_boundary(hops: list[ReceivedHopRaw]) -> tuple[int, list[Fact]]:
    """
    Walks hops in order (index 0 = newest/topmost, matching CanonicalEmail
    convention). Returns the index of the LAST hop still inside the
    trusted boundary (i.e. the deepest/oldest hop whose 'by' claim matched
    a trusted pattern while every hop from 0..that index also matched),
    or -1 if hop 0 itself is not trusted (no trusted boundary at all).

    Also returns Facts documenting each trust decision, for auditability.
    """
    facts: list[Fact] = []
    boundary_index = -1
    for hop in hops:
        pattern = by_claim_matches_trusted(hop.by_claim)
        if pattern is not None:
            boundary_index = hop.sequence_index
            facts.append(
                _fact(
                    f"routing-trust-{hop.sequence_index}",
                    "routing",
                    "hop_trust_evaluation",
                    SignalState.PRESENT,
                    f"trusted:{pattern.provider}",
                    detail=(
                        f"Hop {hop.sequence_index} 'by' claim matched trusted "
                        f"pattern '{pattern.label}' (config {TRUSTED_RECEIVERS_VERSION})."
                    ),
                )
            )
            continue
        else:
            facts.append(
                _fact(
                    f"routing-trust-{hop.sequence_index}",
                    "routing",
                    "hop_trust_evaluation",
                    SignalState.PRESENT,
                    "untrusted_or_unrecognized",
                    detail=(
                        f"Hop {hop.sequence_index} 'by' claim did not match any "
                        f"pattern in trusted-receiver config {TRUSTED_RECEIVERS_VERSION}; "
                        f"boundary walk stops here."
                    ),
                )
            )
            break
    return boundary_index, facts


def _detect_temporal_contradiction(hops: list[ReceivedHopRaw]) -> list[Fact]:
    """
    Chain is newest-first (index 0 newest). Walking from newest to oldest,
    each subsequent (older) hop's timestamp should be <= the previous
    (newer) hop's timestamp, within TEMPORAL_TOLERANCE. A violation beyond
    tolerance is a temporal contradiction.
    """
    facts: list[Fact] = []
    timestamped = [h for h in hops if h.timestamp_parsed is not None]
    
    import datetime
    def to_utc(dt):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
        
    for newer, older in zip(timestamped, timestamped[1:]):
        t_older = to_utc(older.timestamp_parsed)
        t_newer = to_utc(newer.timestamp_parsed)
        # older hop's time should not be AFTER newer hop's time (allowing tolerance)
        if t_older > t_newer + TEMPORAL_TOLERANCE:
            delta = t_older - t_newer
            facts.append(
                _fact(
                    f"routing-temporal-{newer.sequence_index}-{older.sequence_index}",
                    "routing",
                    "temporal_contradiction_beyond_tolerance",
                    SignalState.PRESENT,
                    f"{delta}",
                    detail=(
                        f"Hop {older.sequence_index} timestamp is {delta} later than "
                        f"hop {newer.sequence_index}, exceeding tolerance "
                        f"{TEMPORAL_TOLERANCE}, given the chain is walked "
                        f"newest-to-oldest from hop 0."
                    ),
                )
            )
    return facts


def _detect_structural_implausibility(hops: list[ReceivedHopRaw], boundary_index: int) -> list[Fact]:
    """
    Within the trusted boundary segment only (hops 0..boundary_index),
    check that each hop's 'from' claim is structurally consistent with
    the 'by' claim of the adjacent newer hop (i.e. the chain of custody
    is contiguous). This deliberately only evaluates the ALREADY-TRUSTED
    segment; it is not used to judge untrusted hops, which are simply
    outside the boundary by definition.

    IMPORTANT (real-world cloud infra calibration): large providers
    (Gmail, Microsoft 365) legitimately hand a message between many
    differently-named internal nodes of the SAME provider - exact
    hostname equality between adjacent hops is NOT a valid consistency
    requirement and produces false positives on real M365/Gmail chains.
    This check therefore only flags a mismatch when the two hostnames
    resolve to DIFFERENT trusted-provider families (e.g. one hop's
    'from' claim is a Google host while the adjacent trusted hop's 'by'
    claim is a Microsoft host) - i.e. an actual cross-provider identity
    break within what is supposed to be a single continuous trusted
    boundary. Same-family (or unresolvable-family) adjacent hostnames
    are never flagged here.
    """
    facts: list[Fact] = []
    if boundary_index < 1:
        return facts
    trusted_segment = [h for h in hops if h.sequence_index <= boundary_index]
    for newer, older in zip(trusted_segment, trusted_segment[1:]):
        if not newer.from_claim or not older.by_claim:
            continue  # insufficient data - not implausibility, just unavailable
        newer_from_token = newer.from_claim.strip().split()[0].lower()
        older_by_token = older.by_claim.strip().split()[0].lower()
        if newer_from_token == older_by_token:
            continue

        newer_family = hostname_trust_family(newer_from_token)
        older_family = hostname_trust_family(older_by_token)

        if newer_family is not None and older_family is not None and newer_family != older_family:
            facts.append(
                _fact(
                    f"routing-structural-{newer.sequence_index}-{older.sequence_index}",
                    "routing",
                    "structural_implausibility",
                    SignalState.PRESENT,
                    f"{newer_from_token}({newer_family}) != {older_by_token}({older_family})",
                    detail=(
                        f"Within the trusted boundary, hop {newer.sequence_index}'s "
                        f"'from' claim ('{newer_from_token}', provider family "
                        f"'{newer_family}') is inconsistent with hop "
                        f"{older.sequence_index}'s 'by' claim ('{older_by_token}', "
                        f"provider family '{older_family}') - a cross-provider "
                        f"identity break within what should be a single continuous "
                        f"trusted boundary."
                    ),
                )
            )
    return facts


def analyze_routing(email: CanonicalEmail) -> AnalyzerOutput:
    facts: list[Fact] = []
    candidates: list[FindingCandidate] = []
    hops = email.received_chain_raw

    if not hops:
        facts.append(
            _fact(
                "routing-no-chain",
                "routing",
                "received_chain_present",
                SignalState.ABSENT,
                None,
                detail="No Received headers were found in this message.",
            )
        )
        facts.append(
            _fact(
                "routing-hop0-ip",
                "routing",
                "hop0_candidate_ip",
                SignalState.UNAVAILABLE,
                None,
                detail=(
                    "Origin is indeterminate: no Received chain to walk. "
                    "This is recorded as an unavailable signal only. No "
                    "FindingCandidate is emitted for this condition - it is "
                    "not a confirmed registry qualification code, and an "
                    "unavailable signal must never be represented as a "
                    "finding of any kind."
                ),
            )
        )
        return AnalyzerOutput(ANALYZER_NAME, ANALYZER_VERSION, facts, candidates)

    facts.append(
        _fact(
            "routing-chain-length",
            "routing",
            "received_chain_length",
            SignalState.PRESENT,
            len(hops),
        )
    )

    boundary_index, trust_facts = _establish_trust_boundary(hops)
    facts.extend(trust_facts)

    if boundary_index == -1:
        facts.append(
            _fact(
                "routing-hop0-ip",
                "routing",
                "hop0_candidate_ip",
                SignalState.UNAVAILABLE,
                None,
                detail=(
                    "No trusted receiving boundary could be established from "
                    "hop 0 - the newest Received header's 'by' claim did not "
                    "match any v1 trusted-receiver pattern. Origin is "
                    "indeterminate rather than assumed. No FindingCandidate "
                    "is emitted for this condition - it is not a confirmed "
                    "registry qualification code, and an unavailable signal "
                    "must never be represented as a finding of any kind."
                ),
            )
        )
    else:
        boundary_hop = next(h for h in hops if h.sequence_index == boundary_index)
        if boundary_hop.observed_ip:
            facts.append(
                _fact(
                    "routing-hop0-ip",
                    "routing",
                    "hop0_candidate_ip",
                    SignalState.PRESENT,
                    boundary_hop.observed_ip,
                    detail=(
                        f"Candidate probable-origin IP recorded by the last "
                        f"trusted hop (sequence_index={boundary_index}) at the "
                        f"boundary of trusted receivers. This is the observed IP "
                        f"as claimed in that trusted hop's own record, not a "
                        f"claim from an untrusted party."
                    ),
                )
            )
        else:
            facts.append(
                _fact(
                    "routing-hop0-ip",
                    "routing",
                    "hop0_candidate_ip",
                    SignalState.UNAVAILABLE,
                    None,
                    detail=(
                        f"Trusted boundary established at hop {boundary_index}, "
                        f"but no IP literal could be extracted from its 'from' clause."
                    ),
                )
            )

    # --- CF-06 detection: only the three validated conditions ---

    temporal_facts = _detect_temporal_contradiction(hops)
    facts.extend(temporal_facts)
    temporal_code = "CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE"
    temporal_cat, temporal_str = _get_qual_meta(temporal_code)
    for f in temporal_facts:
        candidates.append(
            FindingCandidate(
                category=temporal_cat,
                qualification_code=temporal_code,
                qualification_version=VOCABULARY_VERSION,
                strength=temporal_str,
                normalized_subject=email.id,
                normalized_target=None,
                claim_signature="temporal_contradiction_beyond_tolerance",
                supporting_fact_ids=[f.fact_id],
                supporting_text=f.detail,
                produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
            )
        )

    structural_facts = _detect_structural_implausibility(hops, boundary_index)
    facts.extend(structural_facts)
    structural_code = "CF-06:STRUCTURAL_IMPLAUSIBILITY"
    structural_cat, structural_str = _get_qual_meta(structural_code)
    for f in structural_facts:
        candidates.append(
            FindingCandidate(
                category=structural_cat,
                qualification_code=structural_code,
                qualification_version=VOCABULARY_VERSION,
                strength=structural_str,
                normalized_subject=email.id,
                normalized_target=None,
                claim_signature="structural_implausibility",
                supporting_fact_ids=[f.fact_id],
                supporting_text=f.detail,
                produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
            )
        )

    # CF-06: INDEPENDENT_TRUSTED_CONTRADICTION
    # A deterministic routing qualification indicating that explicitly trusted
    # receiver/relay evidence independently contradicts a relevant claimed or observed
    # email routing path.
    # Requirements:
    # - identify the relevant routing/path claim,
    # - identify the trusted receiver/relay evidence,
    # - show the contradiction,
    # - identify the affected hop(s),
    # - identify the trusted source/evidence,
    # - preserve supporting fact IDs.
    if boundary_index >= 0:
        trusted_hops_info = []
        for h in hops:
            if h.sequence_index <= boundary_index and h.by_claim:
                pattern = by_claim_matches_trusted(h.by_claim)
                if pattern is not None:
                    by_token = h.by_claim.strip().split()[0].lower()
                    trusted_hops_info.append((h, by_token, pattern))

        for hop in hops:
            if hop.sequence_index <= boundary_index + 1:
                continue  # adjacent/inside hops already covered by structural check
            if not hop.from_claim:
                continue
            from_token = hop.from_claim.strip().split()[0].lower()

            for thop, trusted_host, pattern in trusted_hops_info:
                # Contradiction condition: an untrusted hop claims to route from a host
                # that matches or belongs to a trusted receiver/relay, but the observed
                # transmission evidence contradicts the trusted provider's verified infrastructure.
                matches_trusted_host = (
                    from_token == trusted_host
                    or (pattern.by_hostname_suffixes and any(
                        from_token == s or from_token.endswith("." + s)
                        for s in pattern.by_hostname_suffixes
                    ))
                )
                if not matches_trusted_host:
                    continue

                # Check if observed infrastructure contradicts trusted provider
                observed_family = hostname_trust_family(hop.observed_ip) if hop.observed_ip else None
                paren_match = None
                if "(" in hop.from_claim and ")" in hop.from_claim:
                    inside_parens = hop.from_claim.split("(", 1)[1].split(")", 1)[0].strip()
                    paren_token = inside_parens.split()[0].lower() if inside_parens else ""
                    if paren_token:
                        paren_match = hostname_trust_family(paren_token)

                is_contradiction = False
                if hop.observed_ip and (observed_family is None or observed_family != pattern.provider):
                    is_contradiction = True
                elif paren_match is not None and paren_match != pattern.provider:
                    is_contradiction = True
                elif hop.sequence_index > boundary_index + 1:
                    is_contradiction = True

                if is_contradiction:
                    fid = f"routing-independent-contradiction-{hop.sequence_index}"
                    trusted_fact_id = f"routing-trust-{thop.sequence_index}"
                    obs_str = hop.observed_ip or "untrusted infrastructure"
                    detail = (
                        f"Independent trusted contradiction established: untrusted hop {hop.sequence_index} "
                        f"claims routing path from trusted host '{from_token}', but the observed transmission source "
                        f"({obs_str}) contradicts trusted provider '{pattern.provider}' infrastructure, "
                        f"independently contradicting trusted receiver record at hop {thop.sequence_index} "
                        f"({thop.by_claim}, source evidence: {trusted_fact_id})."
                    )
                    fact = _fact(
                        fid,
                        "routing",
                        "independent_trusted_contradiction",
                        SignalState.PRESENT,
                        from_token,
                        detail=detail,
                    )
                    facts.append(fact)
                    ind_code = "CF-06:INDEPENDENT_TRUSTED_CONTRADICTION"
                    ind_cat, ind_str = _get_qual_meta(ind_code)
                    candidates.append(
                        FindingCandidate(
                            category=ind_cat,
                            qualification_code=ind_code,
                            qualification_version=VOCABULARY_VERSION,
                            strength=ind_str,
                            normalized_subject=email.id,
                            normalized_target=None,
                            claim_signature="independent_trusted_contradiction",
                            supporting_fact_ids=[fid, trusted_fact_id],
                            supporting_text=detail,
                            produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
                        )
                    )
                    break  # Emit once per untrusted hop

    # Generic malformedness -> Fact only, never auto-promoted to CF-06.
    for hop in hops:
        if hop.parse_state != SignalState.PRESENT:
            facts.append(
                _fact(
                    f"routing-malformed-{hop.sequence_index}",
                    "routing",
                    "hop_malformed",
                    hop.parse_state,
                    hop.malformed_reason,
                    detail=(
                        f"Hop {hop.sequence_index} could not be fully structurally "
                        f"parsed ({hop.malformed_reason}). This is recorded as a "
                        f"parse-quality fact only; it does not by itself "
                        f"constitute routing fabrication (CF-06)."
                    ),
                )
            )

    return AnalyzerOutput(ANALYZER_NAME, ANALYZER_VERSION, facts, candidates)
