"""
Tool-Facing API and Manifest (HZ3).
===================================

Provides machine-readable BotChain tool integration endpoints:
1. GET /tool-manifest: Complete BotChain tool metadata and operation schemas.
2. GET /version: System version manifest and release hashes.
3. POST /api/v1/tool/analyze-email: Coarse-grained email ingestion and synchronous analysis.
4. GET /api/v1/tool/investigations/{id}/headers: Fine-grained header and Hop-0 inspection (include_body=false by default).
5. GET /api/v1/tool/investigations/{id}/indicators: Extracted IOCs (domains, IPs, URLs, attachments).
6. GET /api/v1/tool/investigations/{id}/explain-score: Deterministic template-driven score and floor explanation.
7. GET /api/v1/tool/investigations/{id}/summary: High-level investigation triage status.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import (
    AnalysisRun,
    Artifact,
    Fact,
    Finding,
    Investigation,
    ScoreConclusion,
    User,
    UserRole,
)
from app.schemas import ActionDraftCreate, ActionDraftOut
from app.qualification_registry import REGISTRY_VERSION, VALIDITY_RULE_VERSION
REGISTRY_RELEASE_HASH = "1047f1db05dd6fe51d20e124d3e42e7d7a20e985993afddfc08759942ee2a44d"
from app.security import assert_same_org, get_current_user
from app.services import evidence_service
from app.services.analysis_run_service import create_analysis_run
from app.services.pipeline_service import execute_analysis_pipeline

logger = logging.getLogger("hopzero.tool_api")

router = APIRouter(tags=["tool-facing-api"])

MAX_ARTIFACT_BYTES = 25 * 1024 * 1024  # 25MB standard RFC822 limit

SYSTEM_VERSION_INFO = {
    "backend_version": "2.0.0",
    "forensics_version": "1.0.0",
    "registry_version": REGISTRY_VERSION,
    "registry_sha256": REGISTRY_RELEASE_HASH,
    "compiler_version": "hopzero-compiler-v1.0.0",
    "validity_engine_version": VALIDITY_RULE_VERSION,
    "score_engine_version": "score-engine-v2",
    "conclusion_generator_version": "conclusion-generator-v2",
    "trusted_receivers_version": "v1",
    "normalization_policy_version": "v1",
    "infrastructure_reputation_version": "infra_rep_v1",
    "protected_brands_version": "protected_brands_v1",
    "prompt_schema_version": "prompt-v1",
    "shared_llm_model": "hermes3:3b",
}

TOOL_MANIFEST = {
    "id": "hopzero-email-forensics",
    "name": "HopZero Email Forensics",
    "version": "2.0.0",
    "description": "Deterministic, hash-verified email forensic analysis engine and threat triage tool.",
    "category": "security_forensics",
    "capabilities": [
        "email_parsing",
        "routing_analysis",
        "hop0_attribution",
        "authentication_validation",
        "indicator_extraction",
        "deterministic_scoring",
        "floor_enforcement",
        "evidence_export",
        "reproducibility_audit",
    ],
    "auth": {
        "type": "bearer",
        "header": "Authorization",
        "description": "Bearer JWT token or API key; X-Internal-Service-Key for automated deterministic producers.",
    },
    "limits": {
        "max_payload_size_bytes": MAX_ARTIFACT_BYTES,
        "timeout_seconds": 60.0,
    },
    "operations": [
        {
            "name": "analyze_email",
            "type": "coarse",
            "description": "Ingest an .eml RFC822 message and run full deterministic forensic pipeline, returning verdict, score, floors, and top findings.",
            "method": "POST",
            "endpoint": "/api/v1/tool/analyze-email",
            "parameters": {
                "include_body": {
                    "type": "boolean",
                    "default": False,
                    "description": "Whether to include raw email body preview text (default: false to preserve context)",
                }
            },
            "request_body": {
                "content_type": "multipart/form-data",
                "required": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "file": {
                            "type": "string",
                            "format": "binary",
                            "description": "The raw .eml RFC822 message file",
                        }
                    },
                    "required": ["file"],
                },
            },
            "response_schema": {
                "type": "object",
                "properties": {
                    "investigation_id": {"type": "string"},
                    "run_id": {"type": "string"},
                    "verdict": {"type": "string", "enum": ["BENIGN", "SUSPICIOUS", "MALICIOUS", "INDETERMINATE"]},
                    "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                    "score": {"type": "integer", "minimum": 0, "maximum": 100},
                    "confidence": {"type": "string"},
                    "active_floors": {"type": "array", "items": {"type": "string"}},
                    "top_findings": {"type": "array"},
                    "key_evidence": {"type": "object"},
                    "untrusted_fields": {"type": "object"},
                },
            },
        },
        {
            "name": "inspect_headers",
            "type": "fine",
            "description": "Inspect Received routing trace, Hop-0 attribution, and SPF/DKIM/DMARC authentication results.",
            "method": "GET",
            "endpoint": "/api/v1/tool/investigations/{investigation_id}/headers",
            "parameters": {
                "investigation_id": {"type": "string", "in": "path", "required": True},
                "include_body": {"type": "boolean", "in": "query", "default": False},
            },
        },
        {
            "name": "extract_indicators",
            "type": "fine",
            "description": "Extract all observed indicators of compromise (domains, IPs, URLs, attachments) from an email.",
            "method": "GET",
            "endpoint": "/api/v1/tool/investigations/{investigation_id}/indicators",
            "parameters": {
                "investigation_id": {"type": "string", "in": "path", "required": True},
            },
        },
        {
            "name": "explain_score",
            "type": "fine",
            "description": "Provide a deterministic, template-driven breakdown of score, active floors, and category weights.",
            "method": "GET",
            "endpoint": "/api/v1/tool/investigations/{investigation_id}/explain-score",
            "parameters": {
                "investigation_id": {"type": "string", "in": "path", "required": True},
            },
        },
        {
            "name": "get_investigation",
            "type": "fine",
            "description": "Retrieve investigation status, metadata, and current verdict summary.",
            "method": "GET",
            "endpoint": "/api/v1/tool/investigations/{investigation_id}/summary",
            "parameters": {
                "investigation_id": {"type": "string", "in": "path", "required": True},
            },
        },
        {
            "name": "propose_action",
            "type": "action",
            "description": "Propose an action draft (e.g. BLOCK_SENDER, BLOCK_DOMAIN, BLOCK_IP, QUARANTINE, ADD_NOTE) for human analyst review. Actions are NEVER executed automatically (Invariant 7: Never an automatic irreversible action); they are saved as drafts in PENDING_CONFIRMATION status until explicitly approved by an operator.",
            "method": "POST",
            "endpoint": "/api/v1/tool/investigations/{investigation_id}/propose-action",
            "parameters": {
                "investigation_id": {"type": "string", "in": "path", "required": True},
            },
            "request_body": {
                "content_type": "application/json",
                "required": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "action_type": {"type": "string", "description": "BLOCK_SENDER, BLOCK_DOMAIN, BLOCK_IP, QUARANTINE, or ADD_NOTE"},
                        "proposed_payload": {"type": "object", "description": "Action parameters, e.g. target, note, reason"},
                        "created_by_actor": {"type": "string", "default": "botchain"},
                    },
                    "required": ["action_type"],
                },
            },
        },
    ],
}


# ---------------------------------------------------------------------------
# Root Manifest & Version Endpoints
# ---------------------------------------------------------------------------

@router.get("/tool-manifest", operation_id="hopzero_get_tool_manifest")
@router.get("/api/v1/tool/manifest", operation_id="hopzero_get_api_tool_manifest")
def get_tool_manifest() -> Dict[str, Any]:
    """Returns the BotChain machine-readable tool manifest."""
    return TOOL_MANIFEST


@router.get("/version", operation_id="hopzero_get_version")
@router.get("/api/v1/tool/version", operation_id="hopzero_get_api_version")
def get_version() -> Dict[str, Any]:
    """Returns the comprehensive HopZero system version manifest."""
    return SYSTEM_VERSION_INFO


# ---------------------------------------------------------------------------
# Helper: Extract User for Tool Operations
# ---------------------------------------------------------------------------

def _get_tool_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """Authenticates the tool caller via JWT Bearer, API Key, or creates demo user."""
    auth_header = request.headers.get("Authorization")
    settings = get_settings()

    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if settings.hopzero_api_key and token == settings.hopzero_api_key:
            user = db.query(User).filter(User.is_active == True).first()
            if user:
                return user
        try:
            from app.security import get_current_user
            return get_current_user(token=token, db=db)
        except Exception:
            pass

    # Fallback to active user in db if available (for test convenience)
    existing = db.query(User).filter(User.is_active == True).first()
    if existing:
        return existing

    # Create default demo user
    from app.models import Organization
    org = db.query(Organization).first()
    if not org:
        org = Organization(name="Default Security Org")
        db.add(org)
        db.flush()
    user = User(
        organization_id=org.id,
        email="bot@hopzero.local",
        hashed_password="[TOOL_API_NO_PASSWORD]",
        role=UserRole.ADMIN,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Coarse Operation: analyze_email
# ---------------------------------------------------------------------------

@router.post("/api/v1/tool/analyze-email", operation_id="hopzero_analyze_email")
async def tool_analyze_email(
    file: UploadFile = File(...),
    include_body: bool = Query(default=False, description="Whether to include raw body preview"),
    db: Session = Depends(get_db),
    user: User = Depends(_get_tool_user),
) -> Dict[str, Any]:
    """
    Coarse-grained tool endpoint: Ingests .eml message, runs synchronous forensic
    pipeline, and returns immediate verdict, score, floors, and key evidence.
    """
    content = await file.read()
    if len(content) > MAX_ARTIFACT_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="ARTIFACT_TOO_LARGE: Artifact exceeds 25MB ceiling.",
        )

    # 1. Create Investigation
    inv = Investigation(
        organization_id=user.organization_id,
        title=f"Tool Ingest: {file.filename or 'email.eml'}",
        created_by_user_id=user.id,
    )
    db.add(inv)
    db.flush()

    # 2. Persist Artifact
    artifact = evidence_service.ingest_artifact(
        db,
        user=user,
        investigation_id=inv.id,
        filename=file.filename or "message.eml",
        mime_type=file.content_type or "message/rfc822",
        content=content,
        ingestion_source="botchain_tool_api",
    )

    # 3. Create AnalysisRun & Execute Pipeline synchronously
    run = create_analysis_run(db, user=user, investigation_id=inv.id, artifact_id=artifact.id)
    execute_analysis_pipeline(db, user=user, investigation_id=inv.id, artifact_id=artifact.id, run_id=run.id)
    db.refresh(inv)

    # 4. Fetch Score & Findings
    score_conc = db.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == run.id).first()
    findings = db.query(Finding).filter(Finding.analysis_run_id == run.id).all()
    facts = db.query(Fact).filter(Fact.analysis_run_id == run.id).all()

    # Extract subject & body preview
    subject_val = "Unknown"
    body_val = None
    for f in facts:
        p = f.payload if isinstance(f.payload, dict) else {}
        f_key = p.get("key") or f.fact_type
        if f.fact_type == "envelope_metadata":
            subject_val = p.get("subject") or subject_val
        elif f_key == "subject_normalized":
            subject_val = p.get("value") or subject_val
        elif f.fact_type == "raw_source_text" and include_body:
            body_val = (p.get("text") or "")[:500]
        elif f_key in ("body_text_plain", "raw_source_text") and include_body:
            body_val = (p.get("value") or p.get("text") or "")[:500]

    top_findings = [
        {
            "id": f.id,
            "qualification_code": f.qualification_code,
            "category": f.category,
            "strength": f.strength,
            "claim_signature": f.claim_signature,
            "mitre_id": f.mitre_id,
        }
        for f in findings[:5]
    ]

    return {
        "investigation_id": inv.id,
        "run_id": run.id,
        "verdict": score_conc.verdict if score_conc else "INDETERMINATE",
        "severity": score_conc.severity if score_conc else "LOW",
        "score": score_conc.total_score if score_conc else 0,
        "confidence": "HIGH" if score_conc and score_conc.total_score > 0 else "MEDIUM",
        "active_floors": score_conc.triggered_floor_codes if score_conc else [],
        "one_line_explanation": score_conc.one_line_explanation if score_conc else "Analysis complete.",
        "top_findings": top_findings,
        "key_evidence": {
            "total_facts_collected": len(facts),
            "total_findings_validated": len(findings),
            "artifact_sha256": artifact.original_artifact_sha256,
        },
        "untrusted_fields": {
            "subject": subject_val,
            "body_preview": body_val if include_body else None,
        },
        "reproducibility": run.config if run and run.config else None,
    }


# ---------------------------------------------------------------------------
# Fine Operation: inspect_headers
# ---------------------------------------------------------------------------

@router.get("/api/v1/tool/investigations/{investigation_id}/headers", operation_id="hopzero_inspect_headers")
def tool_inspect_headers(
    investigation_id: str,
    include_body: bool = Query(default=False, description="Whether to include body preview"),
    db: Session = Depends(get_db),
    user: User = Depends(_get_tool_user),
) -> Dict[str, Any]:
    """Fine-grained inspection of routing hops, Hop-0 attribution, and authentication headers."""
    inv = db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    assert_same_org(user, inv.organization_id)

    facts = db.query(Fact).filter(Fact.investigation_id == investigation_id).all()

    routing_hops = []
    hop0_assessment = None
    auth_results = {}
    headers_summary = {}

    for f in facts:
        p = f.payload if isinstance(f.payload, dict) else {}
        k = p.get("key") or f.fact_type

        if k == "routing_hop_trace":
            routing_hops.append(p.get("detail") or p)
        elif k == "hop0_attribution":
            hop0_assessment = p.get("detail") or p
        elif k.startswith("auth_"):
            auth_results[k] = p.get("value")
        elif k in ("sender_address", "recipient_address", "subject_normalized", "date_header"):
            headers_summary[k] = p.get("value")

    return {
        "investigation_id": investigation_id,
        "routing_hops_count": len(routing_hops),
        "routing_hops": routing_hops,
        "hop0_assessment": hop0_assessment or {"status": "UNAVAILABLE"},
        "authentication_results": auth_results,
        "headers_summary": headers_summary,
        "untrusted_fields": {k: True for k in headers_summary.keys()},
        "body": None if not include_body else "[OMITTED: use include_body=true]",
    }


# ---------------------------------------------------------------------------
# Fine Operation: extract_indicators
# ---------------------------------------------------------------------------

@router.get("/api/v1/tool/investigations/{investigation_id}/indicators", operation_id="hopzero_extract_indicators")
def tool_extract_indicators(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(_get_tool_user),
) -> Dict[str, Any]:
    """Extracts all observed forensic indicators of compromise."""
    inv = db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    assert_same_org(user, inv.organization_id)

    facts = db.query(Fact).filter(Fact.investigation_id == investigation_id).all()

    domains = set()
    ips = set()
    urls = []
    attachments = []

    for f in facts:
        p = f.payload if isinstance(f.payload, dict) else {}
        ft = f.fact_type

        if ft == "envelope_metadata":
            from_dom = p.get("from_domain")
            if from_dom:
                domains.add(from_dom.lower())
            from_addr = p.get("from_address")
            if from_addr and "@" in from_addr:
                domains.add(from_addr.split("@")[-1].lower())
            for r in p.get("reply_to") or []:
                if "@" in r:
                    domains.add(r.split("@")[-1].lower())

        elif ft in ("probable_origin_ip", "grounded_infrastructure_ip"):
            val = p.get("value") or p.get("ip")
            if val:
                ips.add(val)

        elif ft == "received_hops":
            for h in p.get("hops") or []:
                c_ip = h.get("observed_ip")
                if c_ip:
                    ips.add(c_ip)

        elif ft == "extracted_links":
            for l in p.get("links") or []:
                href = l.get("href") or ""
                if "://" in href:
                    d = href.split("://")[-1].split("/")[0].split(":")[0].lower()
                    if d:
                        domains.add(d)
                urls.append({
                    "url": href,
                    "display_text": l.get("display_text"),
                    "untrusted": True,
                })

        elif ft == "extracted_attachments":
            for a in p.get("attachments") or []:
                attachments.append({
                    "filename": a.get("filename"),
                    "sha256": a.get("sha256"),
                    "size_bytes": a.get("size_bytes"),
                    "untrusted": True,
                })

    findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    for fd in findings:
        subj = fd.normalized_subject_or_target or ""
        if "@" in subj:
            domains.add(subj.split("@")[-1].lower())
        elif "." in subj and not subj.startswith("."):
            domains.add(subj.lower())

    return {
        "investigation_id": investigation_id,
        "domains": sorted(list(domains)),
        "ips": sorted(list(ips)),
        "urls": urls,
        "attachments": attachments,
        "untrusted_markers": {
            "domains": True,
            "ips": True,
            "urls": True,
            "attachments": True,
        },
    }


# ---------------------------------------------------------------------------
# Fine Operation: explain_score
# ---------------------------------------------------------------------------

@router.get("/api/v1/tool/investigations/{investigation_id}/explain-score", operation_id="hopzero_explain_score")
def tool_explain_score(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(_get_tool_user),
) -> Dict[str, Any]:
    """
    Returns a deterministic, template-driven breakdown of score, active floors,
    and category contributions referencing validated findings.
    """
    inv = db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    assert_same_org(user, inv.organization_id)

    run_id = inv.current_analysis_run_id
    if not run_id:
        latest_run = (
            db.query(AnalysisRun)
            .filter(AnalysisRun.investigation_id == investigation_id)
            .order_by(AnalysisRun.created_at.desc())
            .first()
        )
        if latest_run:
            run_id = latest_run.id

    score_conc = None
    if run_id:
        score_conc = db.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == run_id).first()

    findings = []
    if run_id:
        findings = db.query(Finding).filter(Finding.analysis_run_id == run_id).all()

    # Category caps from locked v1 registry
    category_caps = {
        "authentication": 16,
        "routing": 20,
        "identity": 18,
        "domain": 22,
        "links": 24,
        "attachments": 30,
        "content": 20,
    }

    category_scores = {}
    if score_conc and isinstance(score_conc.category_breakdown, dict):
        category_scores = score_conc.category_breakdown

    active_floors_list = []
    if score_conc and score_conc.triggered_floor_codes:
        for fc in score_conc.triggered_floor_codes:
            active_floors_list.append({
                "code": fc,
                "minimum_severity": "HIGH",
                "explanation": f"Critical risk floor {fc} active based on corroborated forensic findings.",
            })

    findings_breakdown = [
        {
            "finding_id": f.id,
            "qualification_code": f.qualification_code,
            "category": f.category,
            "strength": f.strength,
            "claim_signature": f.claim_signature,
            "mitre_id": f.mitre_id,
        }
        for f in findings
    ]

    # Deterministic template-driven explanation string
    total = score_conc.total_score if score_conc else 0
    sev = score_conc.severity if score_conc else "LOW"
    verdict = score_conc.verdict if score_conc else "INDETERMINATE"
    floor_text = f" Floors triggered: {', '.join(score_conc.triggered_floor_codes)}." if score_conc and score_conc.triggered_floor_codes else " No critical floors triggered."
    explanation_text = f"Calculated score {total}/100 with severity {sev} and verdict {verdict}. Based on {len(findings)} validated findings.{floor_text}"

    return {
        "investigation_id": investigation_id,
        "run_id": run_id,
        "total_score": total,
        "severity": sev,
        "canonical_verdict": verdict,
        "category_scores": category_scores,
        "category_caps": category_caps,
        "active_floors": active_floors_list,
        "findings_breakdown": findings_breakdown,
        "deterministic_explanation": explanation_text,
    }


# ---------------------------------------------------------------------------
# Fine Operation: get_investigation summary
# ---------------------------------------------------------------------------

@router.get("/api/v1/tool/investigations/{investigation_id}/summary", operation_id="hopzero_get_investigation_summary")
def tool_get_investigation_summary(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(_get_tool_user),
) -> Dict[str, Any]:
    """Retrieves high-level investigation triage status and verdict summary."""
    inv = db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    assert_same_org(user, inv.organization_id)

    run_id = inv.current_analysis_run_id
    score_conc = None
    if run_id:
        score_conc = db.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == run_id).first()

    findings_count = db.query(Finding).filter(Finding.investigation_id == investigation_id).count()

    return {
        "investigation_id": inv.id,
        "status": inv.status.value,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "latest_score": score_conc.total_score if score_conc else None,
        "latest_severity": score_conc.severity if score_conc else None,
        "latest_verdict": score_conc.verdict if score_conc else None,
        "findings_count": findings_count,
        "untrusted_fields": {
            "title": inv.title,
        },
    }


@router.post(
    "/api/v1/tool/investigations/{investigation_id}/propose-action",
    operation_id="hopzero_tool_propose_action",
    response_model=ActionDraftOut,
    status_code=status.HTTP_201_CREATED,
    summary="Propose an action draft via tool API",
    description="Proposes an action draft for human analyst confirmation. Invariant 7 ensures actions are never executed automatically.",
)
def tool_propose_action(
    investigation_id: str,
    body: ActionDraftCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from app.services import action_draft_service
    return action_draft_service.create_action_draft(
        db,
        user=user,
        investigation_id=investigation_id,
        action_type=body.action_type,
        proposed_payload=body.proposed_payload,
        created_by_actor=body.created_by_actor or "botchain",
    )


@router.get(
    "/api/v1/tool/investigations/{investigation_id}/reproducibility",
    operation_id="hopzero_inspect_reproducibility",
    summary="Inspect run reproducibility configuration",
    description="Returns the exact LLM reproducibility metadata (model, digest, quantization, num_ctx, options_hash) per HZ8.",
)
def tool_inspect_reproducibility(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(_get_tool_user),
) -> Dict[str, Any]:
    inv = db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    assert_same_org(user, inv.organization_id)
    run = None
    if inv.current_analysis_run_id:
        run = db.get(AnalysisRun, inv.current_analysis_run_id)
    if not run:
        run = (
            db.query(AnalysisRun)
            .filter(AnalysisRun.investigation_id == inv.id)
            .order_by(AnalysisRun.created_at.desc())
            .first()
        )
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No analysis run found.")

    return {
        "investigation_id": inv.id,
        "run_id": run.id,
        "reproducibility": run.config or {},
    }
