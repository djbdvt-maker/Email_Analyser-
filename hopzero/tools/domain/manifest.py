"""
HopZero Domain & Lookalike Checker - Tool Manifest.
===================================================
Conforms to BotChain Tool Suite Standard (TOOL_SUITE_STANDARD.md).
"""
from typing import Any, Dict

DOMAIN_TOOL_MANIFEST: Dict[str, Any] = {
    "id": "hopzero-domain-checker",
    "name": "HopZero Domain & Lookalike Checker",
    "version": "1.0.0",
    "description": "Deterministic domain reputation, homoglyph confusable, and brand lookalike detection engine.",
    "category": "security_forensics",
    "capabilities": [
        "domain_normalization",
        "punycode_detection",
        "mixed_script_detection",
        "homoglyph_detection",
        "brand_lookalike_detection",
        "typosquatting_detection",
        "batch_inspection",
    ],
    "auth": {
        "type": "bearer",
        "header": "Authorization",
        "description": "Bearer JWT token or API key for authenticated caller identity.",
    },
    "limits": {
        "max_payload_size_bytes": 1024 * 1024,
        "timeout_seconds": 15.0,
        "max_batch_size": 100,
    },
    "operations": [
        {
            "name": "check_domain",
            "type": "coarse",
            "description": "Evaluate a single domain name for lookalike confusable attacks, punycode, mixed-script, and typosquatting against protected brands.",
            "method": "POST",
            "endpoint": "/api/v1/domain/check",
            "parameters": {},
            "request_body": {
                "content_type": "application/json",
                "required": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "The domain name to inspect (e.g. micr0soft-update.com, paypal.com)",
                        },
                        "context": {
                            "type": "object",
                            "description": "Optional context metadata (e.g. source URL or email address)",
                        },
                    },
                    "required": ["domain"],
                },
            },
            "response_schema": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "normalized_domain": {"type": "string"},
                    "is_lookalike": {"type": "boolean"},
                    "is_homoglyph": {"type": "boolean"},
                    "is_punycode": {"type": "boolean"},
                    "is_mixed_script": {"type": "boolean"},
                    "matched_brand": {"type": "string", "nullable": True},
                    "risk_verdict": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                    "facts": {"type": "array"},
                    "findings": {"type": "array"},
                },
            },
        },
        {
            "name": "check_domains_batch",
            "type": "coarse",
            "description": "Evaluate multiple domain names in a single batch call.",
            "method": "POST",
            "endpoint": "/api/v1/domain/check-batch",
            "parameters": {},
            "request_body": {
                "content_type": "application/json",
                "required": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "domains": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of domains to evaluate (max 100)",
                        }
                    },
                    "required": ["domains"],
                },
            },
        },
    ],
}
