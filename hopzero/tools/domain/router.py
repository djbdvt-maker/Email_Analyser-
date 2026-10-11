"""
HopZero Domain & Lookalike Checker - API Router.
================================================
FastAPI router providing discovery, version, and domain inspection endpoints.
All operation IDs are prefixed with 'domain_' (TOOL_SUITE_STANDARD.md).
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from .manifest import DOMAIN_TOOL_MANIFEST
from .service import (
    analyze_domain,
    analyze_domains_batch,
    DomainCheckResult,
    PROTECTED_BRANDS_VERSION,
)

router = APIRouter(tags=["domain-tool"])

DOMAIN_TOOL_VERSION_INFO = {
    "tool_id": "hopzero-domain-checker",
    "tool_version": "1.0.0",
    "protected_brands_version": PROTECTED_BRANDS_VERSION,
}


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class DomainCheckRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253, description="The domain name to analyze (untrusted user input)")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Optional caller context metadata")


class DomainBatchRequest(BaseModel):
    domains: List[str] = Field(..., min_length=1, max_length=100, description="List of domain names to analyze in batch")


class DomainCheckResponse(BaseModel):
    domain: str
    normalized_domain: str
    is_lookalike: bool
    is_homoglyph: bool
    is_punycode: bool
    is_mixed_script: bool
    matched_brand: Optional[str]
    risk_verdict: str
    facts: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    untrusted_fields: Dict[str, str]


class DomainBatchResponse(BaseModel):
    results: List[DomainCheckResponse]
    total_evaluated: int


# ---------------------------------------------------------------------------
# Discovery & Version Endpoints
# ---------------------------------------------------------------------------

@router.get("/api/v1/domain/manifest", operation_id="hopzero_domain_get_manifest")
def get_domain_tool_manifest() -> Dict[str, Any]:
    """Returns the BotChain tool manifest for the Domain & Lookalike Checker."""
    return DOMAIN_TOOL_MANIFEST


@router.get("/api/v1/domain/version", operation_id="hopzero_domain_get_version")
def get_domain_tool_version() -> Dict[str, Any]:
    """Returns version identifiers and dataset release tags."""
    return DOMAIN_TOOL_VERSION_INFO


@router.get("/api/v1/domain/health", operation_id="hopzero_domain_get_health")
def get_domain_tool_health() -> Dict[str, str]:
    """Returns health status."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Inspection Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/api/v1/domain/check",
    response_model=DomainCheckResponse,
    operation_id="hopzero_domain_check_domain",
    summary="Check a single domain",
    description="Inspects a domain name for lookalike, homoglyph, punycode, and brand typosquatting risk signals.",
)
def check_domain_endpoint(body: DomainCheckRequest) -> DomainCheckResponse:
    res: DomainCheckResult = analyze_domain(body.domain, context=body.context)
    return DomainCheckResponse(
        domain=res.domain,
        normalized_domain=res.normalized_domain,
        is_lookalike=res.is_lookalike,
        is_homoglyph=res.is_homoglyph,
        is_punycode=res.is_punycode,
        is_mixed_script=res.is_mixed_script,
        matched_brand=res.matched_brand,
        risk_verdict=res.risk_verdict,
        facts=res.facts,
        findings=res.findings,
        untrusted_fields=res.untrusted_fields,
    )


@router.post(
    "/api/v1/domain/check-batch",
    response_model=DomainBatchResponse,
    operation_id="hopzero_domain_check_domains_batch",
    summary="Check multiple domains in batch",
    description="Batch inspection of up to 100 domain names.",
)
def check_domains_batch_endpoint(body: DomainBatchRequest) -> DomainBatchResponse:
    results: List[DomainCheckResult] = analyze_domains_batch(body.domains)
    mapped = [
        DomainCheckResponse(
            domain=r.domain,
            normalized_domain=r.normalized_domain,
            is_lookalike=r.is_lookalike,
            is_homoglyph=r.is_homoglyph,
            is_punycode=r.is_punycode,
            is_mixed_script=r.is_mixed_script,
            matched_brand=r.matched_brand,
            risk_verdict=r.risk_verdict,
            facts=r.facts,
            findings=r.findings,
            untrusted_fields=r.untrusted_fields,
        )
        for r in results
    ]
    return DomainBatchResponse(results=mapped, total_evaluated=len(mapped))
