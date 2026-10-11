"""
HopZero Forensic Analysis Interface (typed contracts)
======================================================
Backed by the shared core domain package: `hopzero.core.models`.
Preserves 100% backwards-compatibility for existing imports.
"""
from __future__ import annotations

from hopzero.core.models import (
    SignalState,
    RawHeader,
    EmailAddress,
    ReceivedHopRaw,
    ExtractedLink,
    ExtractedAttachment,
    EmailBody,
    CanonicalEmail,
    Fact,
    FindingCandidate,
    AnalyzerOutput,
    NormalizationEvent,
    NormalizedField,
    NormalizedEvidence,
    NormalizedEntity,
    AnalysisRunConfig,
)

__all__ = [
    "SignalState",
    "RawHeader",
    "EmailAddress",
    "ReceivedHopRaw",
    "ExtractedLink",
    "ExtractedAttachment",
    "EmailBody",
    "CanonicalEmail",
    "Fact",
    "FindingCandidate",
    "AnalyzerOutput",
    "NormalizationEvent",
    "NormalizedField",
    "NormalizedEvidence",
    "NormalizedEntity",
    "AnalysisRunConfig",
]
