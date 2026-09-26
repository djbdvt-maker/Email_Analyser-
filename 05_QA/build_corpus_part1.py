"""
HopZero SECURITY_EVALUATION_CORPUS_V1 - generation script, part 1 (families A-C).
Boundary discipline enforced throughout:
  - expected_qualification_code, expected_claim_signature, expected_strength,
    expected_score are NEVER filled with a guess. They are null unless an
    authoritative artifact explicitly confirmed the exact value.
  - expected_severity is only filled with a concrete value when a locked
    floor rule (CF-01..CF-06, or the 18-point auth cap) makes the DIRECTION
    unambiguous (e.g. "minimum High" or "cannot reach High from this alone").
    Otherwise null.
  - confirmation_level lists which of A-E are actually confirmed for this
    case, per the source-discipline scheme in the task brief.
"""

# ---------------------------------------------------------------------------
# Reusable source references
# ---------------------------------------------------------------------------

SRC_BRIEF = {
    "source": "architecture requirement",
    "reference": "HopZero SIH2026 project brief - core pipeline description and rules 1-10 (deterministic facts, LLM-does-not-set-verdict/score, Hop-0=candidate-not-attacker, missing-signals-unavailable-not-clean, local-first MVP)",
    "supports": "A",
}

SRC_FLOOR_REVIEW = {
    "source": "explicitly locked AI/scoring rule",
    "reference": "Architecture review message (Phase 1 correction pass) - CF-01..CF-06 floor definitions, and the 18-point cap on the authentication scoring category with no generic auth-failure floor",
    "supports": "A",
}

SRC_TASK_BRIEF = {
    "source": "other project artifact",
    "reference": "Person 5 Task 1 - Security Evaluation Corpus specification (current task message defining required case families, H1/H2 semantics, evasion classes, contradiction-handling requirements)",
    "supports": "A",
}

def SRC_PHASE1(fixture_id):
    return {
        "source": "existing test/fixture",
        "reference": f"HopZero QA Phase 1 corpus (corrected) - fixtures/{fixture_id}.eml + expected/{fixture_id}.expected.json",
        "supports": "A",
    }

SRC_PERSON3_MISSING = {
    "source": "Person 3 parser/routing behavior",
    "reference": "NOT PROVIDED to QA in this conversation. Person 3's actual package (parser/security baseline, routing/Hop-0 tests, Evidence Normalizer tests, and the three confirmed CF-06 qualification codes) was referenced by name in the task brief but the artifact itself was never shared with Person 5. This case is built ONLY from the architecture-level CF-06 concept definitions already confirmed in the Phase 1 floor review (temporal contradiction / independent trusted contradiction / structural implausibility), NOT from Person 3's actual fixtures or his literal code strings, per the explicit instruction not to recreate his work from memory.",
    "supports": "GAP - flagged, not confirmed",
}

CASES = []

def case(cid, title, family, input_desc, behavior, concepts, sources,
         ai_relevant=False, evasion_class=None, severity=None, notes="",
         confirmation=("A",)):
    CASES.append({
        "case_id": cid,
        "title": title,
        "scenario_type": family,
        "input_description": input_desc,
        "expected_behavior": behavior,
        "expected_concepts": concepts,
        "expected_qualification_code": None,
        "expected_claim_signature": None,
        "expected_strength": None,
        "expected_score": None,
        "expected_severity": severity,
        "ai_relevant": ai_relevant,
        "evasion_class": evasion_class,
        "notes": notes,
        "source_references": sources,
        "confirmation_level": list(confirmation),
    })

# ===========================================================================
# FAMILY A - BENIGN / BASELINE (5 cases)
# ===========================================================================

case("SEC-001", "Clean legitimate business email", "A. Benign/Baseline",
     "Ordinary internal or B2B business correspondence, fully aligned SPF/DKIM/DMARC, no urls/attachments, no urgency or financial content.",
     ["All deterministic categories should read as clean/aligned.",
      "No CF-01..CF-06 floor should trigger.",
      "Overall severity should sit at the lowest band the scoring system defines."],
     ["clean authentication", "no floor conditions present"],
     [SRC_BRIEF, SRC_PHASE1("01_legit_gmail")],
     severity=None,
     notes="Corresponds directly to Phase 1 fixture 01. Exact lowest-band label is not confirmed to QA, so severity stays null even though direction (lowest) is known.")

case("SEC-002", "Legitimate urgent business email", "A. Benign/Baseline",
     "Genuine last-minute business request (e.g. meeting moved up, deliverable needed sooner) with clean authentication and no financial or credential request.",
     ["Urgency language alone, without a CF-02 Group 2 financial/payment request or Group 1 executive-identity claim, must not trigger CF-02.",
      "Must not be scored the same as a BEC case that pairs urgency with a financial/identity claim."],
     ["urgency without floor-qualifying second condition"],
     [SRC_FLOOR_REVIEW, SRC_PHASE1("08_legit_urgent_business")],
     notes="Paired contrast case with SEC-022 (executive impersonation + financial request) and SEC-023 (urgency without malicious intent).",
     confirmation=("A", "E"))

case("SEC-003", "Legitimate email with unusual but valid routing", "A. Benign/Baseline",
     "Email that traverses an atypical but structurally plausible relay path (e.g. legitimate third-party mail security gateway, legitimate multi-region enterprise relay) with no temporal contradiction, no independent trusted contradiction, and no structural implausibility.",
     ["Unusual routing shape alone, absent the three specific CF-06 trigger conditions, must not trigger CF-06.",
      "Generic 'looks unusual' must not be treated as equivalent to 'fabricated'."],
     ["plausible-but-unusual routing is not automatically a routing-fabrication signal"],
     [SRC_FLOOR_REVIEW, SRC_TASK_BRIEF],
     notes="Exact routing fixture not available (Person 3 package not provided) - behavior stated at the concept level only.",
     confirmation=("A", "E"))

case("SEC-004", "Legitimate email with authentication irregularity caused by forwarding", "A. Benign/Baseline",
     "Legitimate email forwarded through an intermediary (mailing list, forwarding rule) that causes SPF to fail or DKIM to break due to header rewriting, while the message is not actually malicious.",
     ["Authentication failure caused by forwarding must still be reported factually as a failure (rule: deterministic facts computed deterministically) - it must NOT be silently reclassified as 'pass' because the cause is benign.",
      "Authentication alone (max 18 points, no generic auth-failure floor) must not by itself push this to High severity.",
      "Whether a distinct 'forwarding-consistent auth break' concept exists as its own registry item is unknown to QA."],
     ["auth failure with a benign known cause", "authentication category capped, not an independent floor"],
     [SRC_FLOOR_REVIEW, SRC_TASK_BRIEF],
     notes="This is the deferred 'forwarded/relayed email' case type from Phase 1 planning, now specified behaviorally rather than built as a fixture yet.",
     confirmation=("A", "E"))

case("SEC-005", "Legitimate multilingual email", "A. Benign/Baseline",
     "Ordinary legitimate business email written in a non-English language (or mixing scripts, e.g. English subject + local-language body) with clean authentication.",
     ["Non-English/non-Latin body content must not itself be treated as suspicious or as unavailable/uninterpretable.",
      "Mixed-script BODY content is explicitly distinguished from mixed-script DOMAIN content (see family F note): confusable/skeleton comparison is domain-specific and must not be applied to arbitrary body text.",
      "Semantic/content analysis, if it runs, must not penalize language choice itself as a signal."],
     ["language is not itself a security signal", "confusable-folding is domain-scoped, not body-text-scoped"],
     [SRC_TASK_BRIEF],
     notes="Directly reflects the task brief's explicit warning under family F, applied here to the benign baseline.")

# ===========================================================================
# FAMILY B - ROUTING / HOP-0 (9 cases, 6-14)
# ===========================================================================
# NOTE: Person 3's actual package was not provided to QA. Every case in this
# family is built from the architecture-level CF-06 concept definitions only.
# The literal CF-06 qualification code strings are unknown and are NOT
# invented here.

case("SEC-006", "Legitimate Gmail chain", "B. Routing/Hop-0",
     "Single/double-hop Gmail consumer ESP relay chain, structurally standard.",
     ["Candidate probable-origin IP is Google infrastructure, must be labelled candidate-origin, never 'attacker IP' (rule 6).",
      "No CF-06 condition present -> CF-06 must not trigger."],
     ["Hop-0 is candidate-origin only", "no routing-fabrication condition present"],
     [SRC_BRIEF, SRC_PHASE1("01_legit_gmail"), SRC_PERSON3_MISSING],
     notes="Reuses Phase 1 fixture 01 as the concrete instance; Person 3's own routing-test equivalent, if one exists, was not available for cross-reference.")

case("SEC-007", "Legitimate Microsoft 365 chain", "B. Routing/Hop-0",
     "Multi-hop (3+) M365 tenant-to-tenant relay chain, structurally standard for that ESP.",
     ["Multi-hop count alone, for a recognized legitimate ESP pattern, must not be penalized or treated as suspicious.",
      "CF-06 must not trigger absent one of the three specific conditions."],
     ["hop count is not itself a risk signal", "ESP-family-consistent multi-hop routing is plausible"],
     [SRC_BRIEF, SRC_PHASE1("02_legit_m365"), SRC_PERSON3_MISSING],
     notes="Reuses Phase 1 fixture 02.")

case("SEC-008", "Unknown/unrecognized relay boundary", "B. Routing/Hop-0",
     "Email transits through relay infrastructure that does not match any recognized major-ESP signature but is not otherwise anomalous (no temporal/structural/trust contradiction).",
     ["'Unrecognized' must be represented as its own state, distinct from both 'known-legitimate' and 'known-bad'.",
      "Must not default to either a clean or a malicious interpretation purely because the relay is unrecognized (rule 7 applies to routing evidence too: unavailable/unrecognized is not the same as clean, and is also not automatically malicious)."],
     ["unrecognized infrastructure is a distinct evidentiary state, not a verdict"],
     [SRC_BRIEF, SRC_TASK_BRIEF, SRC_PERSON3_MISSING],
     notes="Corresponds to the 'legitimate unrecognized relay' fixture category deferred from Phase 1 planning.")

case("SEC-009", "No Received chain", "B. Routing/Hop-0",
     "Zero Received headers present in the message.",
     ["received_hop_count = 0 is a KNOWN, confirmed fact and must be reported as such, never as 'unavailable'.",
      "origin_determination = unavailable; candidate_probable_origin_ip = null/unavailable.",
      "Must not default to a clean/benign verdict purely because no negative routing signal was found (rule 7).",
      "Whether zero Received headers itself qualifies as CF-06 'specific structural implausibility' is an OPEN QUESTION, not assumed true or false here."],
     ["hop-count-known vs origin-determination-unavailable are distinct facts", "absence of evidence is not evidence of cleanliness"],
     [SRC_FLOOR_REVIEW, SRC_PHASE1("10_no_received_chain")],
     notes="Directly reuses the corrected Phase 1 fixture 10 terminology fix (received_hop_count vs origin_determination).",
     confirmation=("A",))

case("SEC-010", "No trusted boundary at hop 0", "B. Routing/Hop-0",
     "Received chain exists, but no hop in the chain corresponds to infrastructure the system has any basis to trust (no recognized ESP, no known corporate MTA, no prior-seen infrastructure).",
     ["Distinct from SEC-009 (zero hops): here hops exist but none is a trust anchor.",
      "Must be represented as a distinct low-confidence-origin state, not conflated with either 'no chain at all' or 'hostile infrastructure confirmed'."],
     ["absence of a trust anchor is its own state, distinct from hostile-infrastructure-confirmed"],
     [SRC_BRIEF, SRC_TASK_BRIEF, SRC_PERSON3_MISSING],
     notes="")

case("SEC-011", "Temporal contradiction", "B. Routing/Hop-0",
     "Received-header timestamps in the chain are internally inconsistent beyond a defined tolerance (e.g. a later hop's timestamp precedes an earlier hop's timestamp by more than the tolerance window).",
     ["This is one of the three explicitly validated CF-06 trigger conditions.",
      "If genuinely beyond tolerance, expected to satisfy CF-06 -> minimum High severity, PER THE LOCKED FLOOR DEFINITION.",
      "The exact tolerance value/threshold is unknown to QA and must not be guessed."],
     ["temporal contradiction beyond tolerance (named CF-06 trigger condition)"],
     [SRC_FLOOR_REVIEW, SRC_PERSON3_MISSING],
     severity="minimum High (IF the contradiction is confirmed to exceed the tolerance threshold - exact tolerance value unknown to QA)",
     notes="This is a named CF-06 trigger condition, so the DIRECTION (triggers CF-06, minimum High) is confirmed at the concept level even without Person 3's package. The tolerance threshold itself is not.",
     confirmation=("A", "E"))

case("SEC-012", "Structural provider-family contradiction", "B. Routing/Hop-0",
     "Received chain claims a hop belongs to one infrastructure/provider family (e.g. claims to be Google infrastructure) but structural header characteristics are inconsistent with that provider family's known patterns.",
     ["Interpreted as a candidate instance of CF-06's 'specific structural implausibility' trigger condition.",
      "Must be evaluated against a SPECIFIC, defined structural-implausibility rule, not a vague 'looks off' judgment (per the review's explicit warning that generic malformedness must not automatically become CF-06)."],
     ["structural implausibility (named CF-06 trigger condition) vs. generic malformedness (explicitly excluded)"],
     [SRC_FLOOR_REVIEW, SRC_PERSON3_MISSING],
     notes="QA cannot confirm the exact structural rule Person 3's analyzer uses to detect this - flagged as a gap pending his package.",
     confirmation=("A",))

case("SEC-013", "Independent trusted contradiction", "B. Routing/Hop-0",
     "A hop in the chain contradicts information from an independently trusted source (e.g. a hop claims to be internal infrastructure that a trusted internal record shows does not exist, or contradicts a previously-established trusted routing pattern for that sender).",
     ["Named CF-06 trigger condition; if genuinely met, expected to satisfy CF-06 -> minimum High severity.",
      "What counts as an 'independently trusted source' in the MVP (no external threat-intel required per rule 8) is not fully specified to QA - flagged as an open question, particularly relevant to fixture SEC-...(see SEC-016/017 cross-reference for the auth-failure-own-domain-spoof case from Phase 1 fixture 07, where this exact question was raised)."],
     ["independent trusted contradiction (named CF-06 trigger condition)"],
     [SRC_FLOOR_REVIEW, SRC_PHASE1("07_auth_failure"), SRC_PERSON3_MISSING],
     severity="minimum High (IF the contradiction is confirmed to meet this condition's locked definition - exact predicate unknown to QA)",
     notes="Directly relevant to the still-open Phase 1 question about fixture 07 (own-domain spoof via unrelated infrastructure) - repeated here as its own standalone case rather than resolved.",
     confirmation=("A", "E"))

case("SEC-014", "Generic malformed Received header", "B. Routing/Hop-0",
     "Received header(s) present but structurally broken/malformed (missing fields, unparseable format, duplicate headers with no IP) without meeting any of the three specific CF-06 trigger conditions.",
     ["Explicitly must NOT trigger CF-06 automatically, per the review's instruction that generic malformedness is excluded.",
      "Must be represented as unavailable/degraded-parse evidence (see also SEC-009 and the Phase 1 fixture 09 malformed-email case), not as a routing-fabrication finding."],
     ["generic malformedness is explicitly excluded from CF-06"],
     [SRC_FLOOR_REVIEW, SRC_PHASE1("09_malformed_email")],
     severity="CF-06 explicitly must NOT trigger from this alone",
     notes="This is the clearest negative-control case in family B: confirms the boundary between 'malformed' and 'fabricated'.",
     confirmation=("A", "E"))
