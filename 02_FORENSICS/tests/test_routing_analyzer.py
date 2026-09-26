import os

from hopzero_forensics.analyzers.routing import analyze_routing
from hopzero_forensics.interfaces import SignalState
from hopzero_forensics.parser import parse_eml_file


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _analyze(name: str):
    email = parse_eml_file(os.path.join(FIXTURES, name), artifact_id="art")
    return email, analyze_routing(email)


def _codes(output):
    return {c.qualification_code for c in output.candidates}


def _fact(output, key):
    matches = [f for f in output.facts if f.key == key]
    assert matches, f"expected a fact with key={key}"
    return matches[0]


# ---------------------------------------------------------------------------
# Legitimate infrastructure: must NOT produce false positives.
# These are the shippability-critical cases.
# ---------------------------------------------------------------------------

def test_legit_gmail_to_gmail_no_cf06_and_hop0_present():
    email, output = _analyze("legit_gmail_to_gmail.eml")
    assert _codes(output) == set()
    hop0 = _fact(output, "hop0_candidate_ip")
    assert hop0.state == SignalState.PRESENT
    assert hop0.value == "64.233.170.51"


def test_legit_m365_no_cf06_and_hop0_present():
    email, output = _analyze("legit_m365.eml")
    assert _codes(output) == set()
    hop0 = _fact(output, "hop0_candidate_ip")
    assert hop0.state == SignalState.PRESENT
    assert hop0.value == "40.107.23.51"


def test_legit_forwarded_via_unrecognized_relay_stops_boundary_at_last_trusted_hop():
    """
    Demonstrates the trust boundary correctly STOPPING mid-chain at a
    genuinely unrecognized RECEIVING relay (see the X-Fixture-Note
    headers in the fixture for the exact hop-by-hop breakdown).

    Hop 0 and Hop 1 are Google-trusted. Hop 2's 'by' clause
    ("smtp-relay.corporate-forwarder.example") does not match any v1
    trusted pattern, so the walk stops there. The candidate
    probable-origin IP must be the IP recorded by the LAST TRUSTED hop
    (Hop 1's own from-claim: Google's own record of who it received
    from) - never the corporate-forwarder relay's self-reported IP,
    since that relay is itself untrusted and sits beyond the boundary.
    """
    email, output = _analyze("legit_forwarded_via_unknown_relay.eml")
    # No CF-06 fabrication candidates - an unrecognized relay alone is not fabrication.
    assert "CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE" not in _codes(output)
    assert "CF-06:STRUCTURAL_IMPLAUSIBILITY" not in _codes(output)
    assert "CF-06:INDEPENDENT_TRUSTED_CONTRADICTION" not in _codes(output)

    hop0 = _fact(output, "hop0_candidate_ip")
    assert hop0.state == SignalState.PRESENT
    # Google's own record (Hop 1), not the untrusted relay's self-reported IP.
    assert hop0.value == "209.85.220.52"
    assert hop0.value != "198.51.100.77"

    # Confirm the boundary genuinely stopped at hop 2, rather than this
    # assertion passing for the wrong reason (e.g. no chain at all).
    trust_facts = {f.fact_id: f for f in output.facts if f.key == "hop_trust_evaluation"}
    assert trust_facts["routing-trust-0"].value == "trusted:google"
    assert trust_facts["routing-trust-1"].value == "trusted:google"
    assert trust_facts["routing-trust-2"].value == "untrusted_or_unrecognized"


# ---------------------------------------------------------------------------
# No chain / missing signal handling
# ---------------------------------------------------------------------------

def test_no_received_chain_is_indeterminate_not_clean():
    email, output = _analyze("no_received_chain.eml")
    hop0 = _fact(output, "hop0_candidate_ip")
    assert hop0.state == SignalState.UNAVAILABLE
    # No FindingCandidate is emitted for this condition: there is no
    # confirmed registry code for "origin indeterminate" yet, and an
    # unavailable signal must never be represented as ANY finding -
    # confirmed or invented. Absence of candidates here must not be
    # confused with a "clean" result; that distinction lives in the
    # Fact's SignalState, not in candidate presence/absence.
    assert output.candidates == []


def test_no_trusted_boundary_at_hop0_is_indeterminate_no_candidate():
    """
    Distinct from the no-chain case: a Received chain IS present, but hop
    0's 'by' claim doesn't match any v1 trusted-receiver pattern, so no
    boundary can be established at all. Must also be Facts-only.
    """
    email, output = _analyze("no_trusted_boundary_at_hop0.eml")
    hop0 = _fact(output, "hop0_candidate_ip")
    assert hop0.state == SignalState.UNAVAILABLE
    assert output.candidates == []


# ---------------------------------------------------------------------------
# CF-06 validated conditions - adversarial cases
# ---------------------------------------------------------------------------

def test_temporal_contradiction_detected():
    email, output = _analyze("adversarial_temporal_contradiction.eml")
    assert "CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE" in _codes(output)


def test_structural_implausibility_detected():
    email, output = _analyze("adversarial_structural_implausibility.eml")
    assert "CF-06:STRUCTURAL_IMPLAUSIBILITY" in _codes(output)


def test_independent_trusted_contradiction_detected():
    email, output = _analyze("adversarial_independent_trusted_contradiction.eml")
    assert "CF-06:INDEPENDENT_TRUSTED_CONTRADICTION" in _codes(output)
    cand = next(c for c in output.candidates if c.qualification_code == "CF-06:INDEPENDENT_TRUSTED_CONTRADICTION")
    assert "routing-trust-0" in cand.supporting_fact_ids
    assert "routing-independent-contradiction-2" in cand.supporting_fact_ids
    assert "mx.google.com" in cand.supporting_text
    assert "contradict" in cand.supporting_text.lower()


def test_q40_negative_cases():
    """Q40 must NOT be emitted for missing headers, unknown relays, or clean flows."""
    # Case 1: No received headers -> no Q40
    _, output_no_chain = _analyze("no_received_chain.eml")
    assert "CF-06:INDEPENDENT_TRUSTED_CONTRADICTION" not in _codes(output_no_chain)

    # Case 2: Unknown relay -> no Q40 (UNKNOWN != CONTRADICTORY)
    _, output_unknown = _analyze("legit_forwarded_via_unknown_relay.eml")
    assert "CF-06:INDEPENDENT_TRUSTED_CONTRADICTION" not in _codes(output_unknown)

    # Case 3: Legitimate multi-hop Gmail -> no Q40
    _, output_legit = _analyze("legit_gmail_to_gmail.eml")
    assert "CF-06:INDEPENDENT_TRUSTED_CONTRADICTION" not in _codes(output_legit)



# ---------------------------------------------------------------------------
# Generic malformedness must NEVER auto-promote to CF-06.
# ---------------------------------------------------------------------------

def test_generic_malformed_header_does_not_produce_cf06():
    email, output = _analyze("generic_malformed_header.eml")
    assert _codes(output).isdisjoint(
        {
            "CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE",
            "CF-06:STRUCTURAL_IMPLAUSIBILITY",
            "CF-06:INDEPENDENT_TRUSTED_CONTRADICTION",
        }
    )
    malformed_facts = [f for f in output.facts if f.key == "hop_malformed"]
    assert len(malformed_facts) == 1
    assert malformed_facts[0].state == SignalState.UNAVAILABLE


# ---------------------------------------------------------------------------
# Output contract shape
# ---------------------------------------------------------------------------

def test_analyzer_output_never_assigns_severity_or_score():
    email, output = _analyze("legit_gmail_to_gmail.eml")
    for c in output.candidates:
        assert not hasattr(c, "score")
        assert not hasattr(c, "severity")
        assert c.strength in {"weak", "moderate", "strong"}
