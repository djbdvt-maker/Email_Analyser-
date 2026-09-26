# hopzero_forensics — Email Forensics Module (Person 3 ownership)

**Status: `team3-baseline-v1` — FROZEN and APPROVED.** See
`docs/BASELINE_FREEZE.md` for exact frozen scope and
`docs/FORENSICS_INTEGRATION_CONTRACT.md` for how other components
should integrate with it. Not merged to GitHub — delivered as a review
artifact.

Deterministic email investigation engine for HopZero. Consumes raw
`.eml` bytes, produces `CanonicalEmail`, normalizes analysis-facing text
into a separate `NormalizedEvidence` representation, and runs analyzers
that emit `Facts` + `FindingCandidates` only — no scoring, no verdict.

## Layout

```
hopzero_forensics/
  __init__.py                   # __version__ = "1.0.0", BASELINE_TAG = "team3-baseline-v1"
  interfaces.py                 # CanonicalEmail + all shared typed contracts
                                 #   (also: NormalizedEvidence/NormalizedField/NormalizationEvent)
  qualification_vocab.py        # locked v1 vocabulary subset (routing codes only so far)
  parser.py                     # .eml -> CanonicalEmail
  evidence_normalizer.py        # CanonicalEmail -> NormalizedEvidence (mechanical only)
  config/
    trusted_receivers_v1.py     # versioned Hop-0 trust config (Gmail/M365 v1)
    normalization_policy_v1.py  # versioned zero-width/whitespace normalization policy
  analyzers/
    routing.py                  # Hop-0 / candidate probable-origin IP + CF-06 routing fabrication
    authentication.py           # SPF, DKIM, DMARC, and identifier alignment analyzer
    identity.py                 # Executive impersonation, brand claims, and reply-to/return-path mismatches
    domain.py                   # Lookalike, homoglyph, mixed script, and newly registered domain analysis
    links.py                    # Credential phishing link, display href mismatch, URL shortener detection
    attachments.py              # Suspicious extensions, macro detection, double extensions, archive inspection
    infrastructure.py           # Known-bad ASN, bulletproof hosting, newly observed infra detection

tests/
  fixtures/*.eml                # real-shaped legit + adversarial fixtures
  test_parser.py
  test_parser_security.py       # folded/duplicate headers, malformed input, non-execution, etc.
  test_routing_analyzer.py
  test_evidence_normalizer.py   # zero-width, whitespace, full-width, multilingual, phishing-style, traceability
  test_authentication_analyzer.py
  test_identity_analyzer.py
  test_domain_analyzer.py
  test_links_analyzer.py
  test_attachments_analyzer.py
  test_infrastructure_analyzer.py

docs/
  BASELINE_FREEZE.md                  # what's frozen, frozen test count
  FORENSICS_INTEGRATION_CONTRACT.md   # how to integrate with this module (read this first)
  CANONICAL_EMAIL_SCHEMA.md           # CanonicalEmail schema detail
  ANALYZER_CONTRACT.md                # analyzer contract + routing/Hop-0 design notes + registry blockers
  NORMALIZATION_DESIGN.md             # Evidence Normalizer design + confusable-folding scoping decision
```

## Run tests

```
pip install pytest --break-system-packages
python3 -m pytest tests/ -v
```

77/77 passing as of this delivery.

## Status

- **Frozen baseline (`team3-baseline-v1`):** Parser, CanonicalEmail,
  Routing/Hop-0 analyzer (CF-06's three validated conditions, no
  unconfirmed codes), trusted-receiver v1 config, Evidence Normalizer
  (mechanical Unicode normalization, no confusable folding, no LLM, no
  network) with its versioned policy config.
- **New this round:** signature-only stubs for the six blocked
  analyzers (Authentication, Identity, Domain, Links, Attachments,
  Infrastructure) — each raises `NotImplementedError` rather than
  silently returning an empty result, and each documents its planned
  `CanonicalEmail`/`NormalizedEvidence` field consumption for when it's
  unblocked. No qualification codes, claim signatures, scores,
  severities, or verdicts were invented anywhere in these stubs.
- **Blocked/flagged for the team:** see §8 of
  `docs/FORENSICS_INTEGRATION_CONTRACT.md` and "Remaining registry
  blockers" in `docs/ANALYZER_CONTRACT.md` — the full qualification
  registry file is still not in the repo. Infrastructure's blocker is
  broader than the other five: its category scope itself isn't defined
  yet, not just its codes.
- **Not merged to GitHub** — this package is for review.

## Integration note

This is a Python library/module, not a service. It's meant to be
imported directly (`from hopzero_forensics.parser import parse_eml_file`,
`from hopzero_forensics.evidence_normalizer import normalize_email`,
`from hopzero_forensics.analyzers.routing import analyze_routing`) behind
the shared Forensic Analysis Interface — no HTTP boundary, no
microservice. **Start with `docs/FORENSICS_INTEGRATION_CONTRACT.md`** if
you're building the next layer on top of this module.
