"""
hopzero.core - Shared domain primitives, models, registry, and hashing utilities.
==================================================================================
Reusable package extracted for the HopZero tool suite.
"""

from .hashing import (
    compute_sha256,
    compute_file_sha256,
    canonical_json_hash,
)
from .models import (
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
from .registry import (
    load_registry,
    get_qualification,
    all_qualifications,
    get_floors,
    get_scoring_buckets,
    RegistryVerificationError,
    QualificationEntry,
    StrengthRule,
    FloorDefinition,
    FloorRequirement,
    ScoringBucket,
    STRENGTH_ORDER,
    strength_at_least,
    max_strength,
)
from .isolation import (
    parse_eml_isolated,
    create_fallback_canonical_email,
    DEFAULT_PARSER_TIMEOUT,
    MAX_MIME_RECURSION_DEPTH,
    MAX_MIME_PARTS,
    MAX_ATTACHMENT_BYTES,
    MAX_TOTAL_ATTACHMENT_BYTES,
    MAX_ATTACHMENTS_COUNT,
)

from .paths import (
    get_app_data_root,
    get_artifacts_dir,
    get_default_sqlite_db_path,
    get_logs_dir,
)
from .clock import (
    get_utc_now,
    get_utc_iso,
    set_clock_override,
    reset_clock_override,
    frozen_clock,
)

from .signatures import (
    compute_manifest_checksums,
    sign_manifest,
    verify_manifest_signature,
    verify_directory_against_manifest,
)

__all__ = [
    # Hashing
    "compute_sha256",
    "compute_file_sha256",
    "canonical_json_hash",
    # Models
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
    # Registry
    "load_registry",
    "get_qualification",
    "all_qualifications",
    "get_floors",
    "get_scoring_buckets",
    "RegistryVerificationError",
    "QualificationEntry",
    "StrengthRule",
    "FloorDefinition",
    "FloorRequirement",
    "ScoringBucket",
    "STRENGTH_ORDER",
    "strength_at_least",
    "max_strength",
    # Isolation
    "parse_eml_isolated",
    "create_fallback_canonical_email",
    "DEFAULT_PARSER_TIMEOUT",
    "MAX_MIME_RECURSION_DEPTH",
    "MAX_MIME_PARTS",
    "MAX_ATTACHMENT_BYTES",
    "MAX_TOTAL_ATTACHMENT_BYTES",
    "MAX_ATTACHMENTS_COUNT",
    # Paths & Clock
    "get_app_data_root",
    "get_artifacts_dir",
    "get_default_sqlite_db_path",
    "get_logs_dir",
    "get_utc_now",
    "get_utc_iso",
    "set_clock_override",
    "reset_clock_override",
    "frozen_clock",
    # Hardware & Editions
    "detect_hardware",
    "HardwareProfile",
    "get_or_create_hardware_profile",
    # Signatures & Verification
    "compute_manifest_checksums",
    "sign_manifest",
    "verify_manifest_signature",
    "verify_directory_against_manifest",
]



