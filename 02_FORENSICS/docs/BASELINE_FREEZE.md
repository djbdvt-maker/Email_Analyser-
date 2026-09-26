# Team 3 Baseline Freeze — v1.0.0 / `team3-baseline-v1`

**Approved by:** independent review (this round).
**Frozen scope:** Parser, CanonicalEmail, Routing/Hop-0 analyzer,
Evidence Normalizer. Blocked-analyzer stubs added this round (see
below) are new, not part of the frozen-behavior surface, and carry no
behavior to freeze (they only raise `NotImplementedError`).

## What "frozen" means here

The following are approved and should not be changed in place. Any
future change to their *behavior* (not just internal refactoring) should
bump `hopzero_forensics.__version__` and go through review again, the
same way `config/trusted_receivers_v1.py` and
`config/normalization_policy_v1.py` are already versioned artifacts in
their own right.

- `hopzero_forensics/interfaces.py` — `CanonicalEmail` and all typed
  contracts (`Fact`, `FindingCandidate`, `AnalyzerOutput`,
  `NormalizedEvidence`, `NormalizedField`, `NormalizationEvent`).
- `hopzero_forensics/parser.py` — `.eml` → `CanonicalEmail`.
- `hopzero_forensics/qualification_vocab.py` — the three confirmed
  CF-06 codes.
- `hopzero_forensics/config/trusted_receivers_v1.py` — v1 trust config.
- `hopzero_forensics/analyzers/routing.py` — Hop-0 / CF-06 behavior.
- `hopzero_forensics/evidence_normalizer.py` — mechanical normalization.
- `hopzero_forensics/config/normalization_policy_v1.py` — v1
  normalization policy.

## Frozen test baseline

**77/77 passing** as of this freeze:
- `test_parser.py` — 8
- `test_parser_security.py` — 23
- `test_routing_analyzer.py` — 10
- `test_evidence_normalizer.py` — 30
- `test_blocked_analyzer_stubs.py` — 6 (new this round; asserts the
  blocked analyzers fail loudly rather than silently)

Command: `python3 -m pytest tests/ -v` from the package root.

## Explicitly NOT frozen / not yet built

Authentication, Identity, Domain, Links, Attachments, Infrastructure
analyzers remain unimplemented stubs (`analyzers/authentication.py`,
`identity.py`, `domain.py`, `links.py`, `attachments.py`,
`infrastructure.py`) — see `docs/FORENSICS_INTEGRATION_CONTRACT.md` and
`docs/ANALYZER_CONTRACT.md` for exactly what blocks each one.

## Not merged to GitHub

This package is delivered as a review artifact only. It has not been
merged to the team's shared repository.
