"""
HopZero Core - Shared Domain Models & Typed Contracts.
======================================================
Defines the canonical, run-agnostic contracts that flow between
HopZero parsers, analyzers, score engines, and tool orchestrators.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from .hashing import canonical_json_hash


# ---------------------------------------------------------------------------
# Signal Availability
# ---------------------------------------------------------------------------

class SignalState(str, Enum):
    """
    Tri-state used throughout facts/candidates:
      PRESENT     -> Signal observed and has concrete value.
      ABSENT      -> Signal checked for and confirmed not to exist.
      UNAVAILABLE -> Signal could not be determined (parse failure, timeout).
    UNAVAILABLE must NEVER be interpreted as negative/clean downstream.
    """
    PRESENT = "present"
    ABSENT = "absent"
    UNAVAILABLE = "unavailable"


# ---------------------------------------------------------------------------
# CanonicalEmail Structural Substructures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RawHeader:
    """A single header line as it appeared in the original message."""
    name: str
    value: str
    raw_line: str
    sequence_index: int


@dataclass(frozen=True)
class EmailAddress:
    """A single parsed email address."""
    display_name: Optional[str]
    address: Optional[str]
    raw_value: str
    parse_state: SignalState


@dataclass(frozen=True)
class ReceivedHopRaw:
    """One 'Received:' header trace, minimally structured."""
    sequence_index: int
    raw_line: str
    from_claim: Optional[str]
    by_claim: Optional[str]
    with_claim: Optional[str]
    for_claim: Optional[str]
    observed_ip: Optional[str]
    timestamp_raw: Optional[str]
    timestamp_parsed: Optional[datetime]
    parse_state: SignalState
    malformed_reason: Optional[str]


@dataclass(frozen=True)
class ExtractedLink:
    """A single hyperlink found in HTML or plaintext body."""
    link_id: str
    href: str
    display_text: Optional[str]
    source: str
    context_snippet: Optional[str]


@dataclass(frozen=True)
class ExtractedAttachment:
    """Structural facts about one attachment/MIME part."""
    attachment_id: str
    filename: Optional[str]
    declared_mime_type: Optional[str]
    size_bytes: Optional[int]
    sha256: Optional[str]
    content_disposition: Optional[str]
    is_inline: bool
    within_archive: bool
    parse_state: SignalState


@dataclass(frozen=True)
class EmailBody:
    """Email body representations."""
    text_plain: Optional[str]
    html_sanitized: Optional[str]
    html_available: bool
    links: List[ExtractedLink] = field(default_factory=list)


# ---------------------------------------------------------------------------
# CanonicalEmail
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CanonicalEmail:
    """
    The single normalized representation that ALL downstream analyzers consume.
    Purely descriptive. No score, severity, verdict, or LLM conclusions.
    """
    id: str
    artifact_id: str
    message_id: Optional[str]
    parsed_at: datetime
    headers: List[RawHeader]
    from_addresses: List[EmailAddress]
    reply_to_addresses: List[EmailAddress]
    return_path: Optional[EmailAddress]
    to_addresses: List[EmailAddress]
    cc_addresses: List[EmailAddress]
    received_chain_raw: List[ReceivedHopRaw]
    body: EmailBody
    attachments: List[ExtractedAttachment]
    subject: Optional[str]
    date_raw: Optional[str]
    date_parsed: Optional[datetime]
    parse_warnings: List[str] = field(default_factory=list)
    is_truncated: bool = False


# ---------------------------------------------------------------------------
# Analyzer Output Contracts: Facts + FindingCandidates
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Fact:
    """A deterministic, atomic observation produced by an analyzer."""
    fact_id: str
    category: str
    key: str
    state: SignalState
    value: Optional[str]
    produced_by: str
    detail: Optional[str] = None


@dataclass(frozen=True)
class FindingCandidate:
    """Candidate finding proposing qualification matching registered vocab."""
    category: str
    qualification_code: str
    qualification_version: str
    strength: str
    normalized_subject: Optional[str]
    normalized_target: Optional[str]
    claim_signature: str
    supporting_fact_ids: List[str]
    supporting_text: Optional[str]
    produced_by: str


@dataclass(frozen=True)
class AnalyzerOutput:
    """Standard shape returned by all forensic analyzers."""
    analyzer_name: str
    analyzer_version: str
    facts: List[Fact]
    candidates: List[FindingCandidate]


# ---------------------------------------------------------------------------
# Evidence Normalization Contracts
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NormalizationEvent:
    """A single deterministic, mechanical transformation record."""
    transformation: str
    position: int
    original_span: str
    replacement_span: Optional[str]
    codepoints: str
    detail: Optional[str] = None


@dataclass(frozen=True)
class NormalizedField:
    """One normalized text surface traceable back to original text."""
    field_path: str
    original_text: str
    normalized_text: str
    policy_version: str
    events: List[NormalizationEvent]
    unchanged: bool


@dataclass(frozen=True)
class NormalizedEvidence:
    """The separate, analysis-facing canonical representation."""
    source_canonical_email_id: str
    source_artifact_id: str
    policy_version: str
    produced_by: str
    fields: List[NormalizedField]


# ---------------------------------------------------------------------------
# Cross-Tool Entities & Run Configurations (HZ5 & HZ8 Anchors)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NormalizedEntity:
    """
    Standard normalized entity representation across the HopZero tool suite.
    Enables cross-tool indicator sharing (domain tool, IP tool, email tool).
    """
    entity_type: str                     # "sender" | "domain" | "ip" | "url" | "attachment" | "brand"
    normalized_value: str                # canonical lower-cased form
    raw_value: str                       # verbatim original representation
    provenance: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisRunConfig:
    """
    Typed execution configuration parameters for an analysis run.
    Contains runtime parameters, feature toggles, and reproducibility anchors (HZ8).
    """
    offline_mode: bool = True
    timeout_seconds: float = 60.0
    include_body: bool = False
    max_payload_size_bytes: int = 25 * 1024 * 1024
    registry_version: str = "v1"
    validity_rule_version: str = "vr-v1"
    # LLM reproducibility fields (anchors for HZ8)
    llm_model: Optional[str] = "hermes3:3b"
    llm_digest: Optional[str] = None
    llm_quantization: Optional[str] = None
    llm_num_ctx: int = 4096
    llm_options_hash: Optional[str] = None
    llm_prompt_version: str = "prompt-v1"
    llm_schema_version: str = "proposal-v1"
    extra_options: Dict[str, Any] = field(default_factory=dict)

    def compute_options_hash(self) -> str:
        """
        Computes deterministic SHA-256 hash over LLM options and extra configurations.
        """
        payload = {
            "model": self.llm_model,
            "digest": self.llm_digest,
            "quantization": self.llm_quantization,
            "num_ctx": self.llm_num_ctx,
            "prompt_version": self.llm_prompt_version,
            "schema_version": self.llm_schema_version,
            "extra_options": self.extra_options,
        }
        return canonical_json_hash(payload)

    def compute_reproducibility_fingerprint(self) -> str:
        """
        Computes canonical SHA-256 fingerprint representing the full deterministic
        reproducibility envelope (registry, validity rule, and LLM configuration).
        """
        payload = {
            "registry_version": self.registry_version,
            "validity_rule_version": self.validity_rule_version,
            "offline_mode": self.offline_mode,
            "options_hash": self.options_hash,
        }
        return canonical_json_hash(payload)

    @property
    def options_hash(self) -> str:
        if not self.llm_options_hash:
            self.llm_options_hash = self.compute_options_hash()
        return self.llm_options_hash

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation for database persistence or JSON transmission."""
        opts_hash = self.options_hash
        return {
            "offline_mode": self.offline_mode,
            "timeout_seconds": self.timeout_seconds,
            "include_body": self.include_body,
            "max_payload_size_bytes": self.max_payload_size_bytes,
            "registry_version": self.registry_version,
            "validity_rule_version": self.validity_rule_version,
            "llm": {
                "model": self.llm_model,
                "digest": self.llm_digest,
                "quantization": self.llm_quantization,
                "num_ctx": self.llm_num_ctx,
                "options_hash": opts_hash,
                "prompt_version": self.llm_prompt_version,
                "schema_version": self.llm_schema_version,
            },
            "extra_options": self.extra_options,
            "reproducibility_fingerprint": self.compute_reproducibility_fingerprint(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AnalysisRunConfig:
        """Reconstruct AnalysisRunConfig from dict representation."""
        llm_data = data.get("llm", {})
        return cls(
            offline_mode=data.get("offline_mode", True),
            timeout_seconds=data.get("timeout_seconds", 60.0),
            include_body=data.get("include_body", False),
            max_payload_size_bytes=data.get("max_payload_size_bytes", 25 * 1024 * 1024),
            registry_version=data.get("registry_version", "v1"),
            validity_rule_version=data.get("validity_rule_version", "vr-v1"),
            llm_model=llm_data.get("model", data.get("llm_model", "hermes3:3b")),
            llm_digest=llm_data.get("digest", data.get("llm_digest")),
            llm_quantization=llm_data.get("quantization", data.get("llm_quantization")),
            llm_num_ctx=llm_data.get("num_ctx", data.get("llm_num_ctx", 4096)),
            llm_options_hash=llm_data.get("options_hash", data.get("llm_options_hash")),
            llm_prompt_version=llm_data.get("prompt_version", data.get("llm_prompt_version", "prompt-v1")),
            llm_schema_version=llm_data.get("schema_version", data.get("llm_schema_version", "proposal-v1")),
            extra_options=data.get("extra_options", {}),
        )
