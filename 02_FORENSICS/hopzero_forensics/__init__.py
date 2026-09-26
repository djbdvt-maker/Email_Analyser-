"""
hopzero_forensics - Email Forensics Module (Person 3 ownership)

BASELINE FREEZE: this package version marks the frozen Team 3 baseline
(Parser + CanonicalEmail + Routing/Hop-0 analyzer + Evidence Normalizer),
approved for use by the rest of the team. See docs/BASELINE_FREEZE.md
for the exact frozen scope and docs/FORENSICS_INTEGRATION_CONTRACT.md
for how other components should integrate with it.

Do not modify frozen behavior in place - any change to already-approved
behavior should bump __version__ and go through review again, the same
way config/trusted_receivers_v1.py and config/normalization_policy_v1.py
are themselves versioned artifacts.
"""

__version__ = "1.0.0"
BASELINE_TAG = "team3-baseline-v1"