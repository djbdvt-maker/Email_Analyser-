"""
Pipeline service for HopZero backend.

Orchestrates the deterministic execution flow:
1. Load artifact bytes
2. Parse .eml with hopzero_forensics.parser.parse_eml -> CanonicalEmail
3. Run evidence_normalizer.normalize_email -> NormalizedEvidence
4. Execute all 7 forensic analyzers:
   - Routing (establishes Hop-0 / candidate probable-origin IP)
   - Authentication (SPF, DKIM, DMARC, identifier alignment)
   - Identity (display-name spoofing, reply-to mismatch, executive impersonation)
   - Domain (lookalikes, punycode, entropy)
   - Links (display-vs-href mismatch, shorteners, auth-like paths)
   - Attachments (double extensions, macro docs, archives)
   - Infrastructure (bulletproof hosting matches against probable origin IP)
5. Persist deterministic Facts and Findings to database
6. Score the investigation run with backend Score Engine
7. Mark run COMPLETED and investigation UNDER_REVIEW
"""
import hashlib
import logging
import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any

from sqlalchemy.orm import Session

# Ensure hopzero_forensics is on sys.path
_repo_root = Path(__file__).resolve().parents[3]
_forensics_dir = str(_repo_root / "02_FORENSICS")
if _forensics_dir not in sys.path:
    sys.path.insert(0, _forensics_dir)

from hopzero_forensics.parser import parse_eml
from hopzero_forensics.evidence_normalizer import normalize_email
from hopzero_forensics.analyzers.routing import analyze_routing
from hopzero_forensics.analyzers.authentication import analyze_authentication
from hopzero_forensics.analyzers.identity import analyze_identity
from hopzero_forensics.analyzers.domain import analyze_domain
from hopzero_forensics.analyzers.links import analyze_links
from hopzero_forensics.analyzers.attachments import analyze_attachments
from hopzero_forensics.analyzers.infrastructure import analyze_infrastructure
from hopzero_forensics.analyzers.geolocation import analyze_geolocation
from hopzero_forensics.interfaces import SignalState

from app.models import (
    Artifact,
    Investigation,
    AnalysisRun,
    AnalysisRunStatus,
    InvestigationStatus,
    Fact as FactModel,
    User,
    AuditAction,
)
from app.audit import record_audit_event
from app.schemas import FindingCreate
from app.services.finding_service import persist_finding
from app.services.score_engine_service import compute_and_persist_score, generate_and_persist_conclusion
from app.services.analysis_run_service import transition_run_status
from app.services.investigation_service import get_investigation

logger = logging.getLogger(__name__)


def execute_analysis_pipeline(
    db: Session,
    *,
    user: User,
    investigation_id: str,
    artifact_id: str,
    run_id: str,
    ai_simulated_failure: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes the full forensic analysis pipeline synchronously for an investigation run.
    Integrates deterministic analyzers, AI reasoner, AI trust boundary, and Score Engine.
    """
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    artifact = db.get(Artifact, artifact_id)
    if not artifact or artifact.investigation_id != inv.id:
        raise ValueError(f"Artifact {artifact_id} not found for investigation {investigation_id}")

    run = db.get(AnalysisRun, run_id)
    if not run or run.investigation_id != inv.id:
        raise ValueError(f"AnalysisRun {run_id} not found for investigation {investigation_id}")

    try:
        # 1. Transition to PARSING
        transition_run_status(
            db, user=user, run_id=run.id,
            new_status=AnalysisRunStatus.PARSING,
            investigation_id=inv.id,
        )

        if not os.path.exists(artifact.storage_path):
            raise FileNotFoundError(f"Artifact file missing: {artifact.storage_path}")

        with open(artifact.storage_path, "rb") as f:
            raw_bytes = f.read()

        # Check hash integrity
        calculated_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        if calculated_sha256 != artifact.original_artifact_sha256:
            raise ValueError(
                f"Artifact hash mismatch: expected {artifact.original_artifact_sha256}, got {calculated_sha256}"
            )

        # 2. Parse CanonicalEmail
        canonical_email = parse_eml(raw_bytes, artifact_id=artifact.id)

        # 3. Transition to ANALYZING
        transition_run_status(
            db, user=user, run_id=run.id,
            new_status=AnalysisRunStatus.ANALYZING,
            investigation_id=inv.id,
        )

        # Normalize evidence
        normalized_evidence = normalize_email(canonical_email)

        # 4. Run Analyzers in Parallel
        import concurrent.futures
        
        # Routing must run first because Infrastructure needs its output
        routing_out = analyze_routing(canonical_email)
        probable_origin_ip = None
        for f in routing_out.facts:
            if f.key == "hop0_candidate_ip" and f.state == SignalState.PRESENT and f.value:
                probable_origin_ip = str(f.value)
                break

        # The other 6 analyzers are independent, run them concurrently in threads
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_auth = executor.submit(analyze_authentication, canonical_email)
            future_ident = executor.submit(analyze_identity, canonical_email, normalized_evidence=normalized_evidence)
            future_domain = executor.submit(analyze_domain, canonical_email)
            future_links = executor.submit(analyze_links, canonical_email)
            future_att = executor.submit(analyze_attachments, canonical_email)
            future_infra = executor.submit(analyze_infrastructure, canonical_email, probable_origin_ip=probable_origin_ip)
            
            auth_out = future_auth.result()
            ident_out = future_ident.result()
            domain_out = future_domain.result()
            links_out = future_links.result()
            att_out = future_att.result()
            infra_out = future_infra.result()

        all_outputs = [
            routing_out,
            auth_out,
            ident_out,
            domain_out,
            links_out,
            att_out,
            infra_out,
        ]

        # 5. Persist Facts
        fact_id_map: Dict[str, str] = {}
        for out in all_outputs:
            for f in out.facts:
                fact_row = FactModel(
                    investigation_id=inv.id,
                    analysis_run_id=run.id,
                    fact_type=f.key,
                    payload={
                        "fact_id": f.fact_id,
                        "category": f.category,
                        "state": f.state.value if hasattr(f.state, "value") else str(f.state),
                        "value": f.value,
                        "detail": f.detail,
                    },
                    produced_by="deterministic",
                )
                db.add(fact_row)
                db.flush()
                fact_id_map[f.fact_id] = fact_row.id

        # Persist email content as raw_source_text fact for AI grounding
        email_subject = canonical_email.subject or ""
        email_body_text = canonical_email.body.text_plain or ""
        combined_source_text = f"{email_subject}\n\n{email_body_text}".strip()
        if not combined_source_text:
            combined_source_text = "[No plaintext body extracted]"

        source_text_fact = FactModel(
            investigation_id=inv.id,
            analysis_run_id=run.id,
            fact_type="raw_source_text",
            payload={"text": combined_source_text},
            produced_by="deterministic",
        )
        db.add(source_text_fact)
        db.flush()

        # RUN YARA ENGINE
        try:
            import yara
            yara_rules = yara.compile(filepath=os.path.join(os.path.dirname(__file__), "..", "yara_rules.yar"))
            matches = yara_rules.match(data=raw_bytes)
            for m in matches:
                yara_fact = FactModel(
                    investigation_id=inv.id,
                    analysis_run_id=run.id,
                    fact_type="yara_match",
                    payload={"rule": m.rule, "tags": m.tags, "meta": m.meta},
                    produced_by="yara_engine",
                )
                db.add(yara_fact)
                db.flush()
                # Create finding deterministically
                persist_finding(db, user=user, investigation_id=inv.id, payload=FindingCreate(
                    analysis_run_id=run.id,
                    category="MALWARE",
                    qualification_code="KNOWN_MALWARE_SIGNATURE",
                    qualification_version="1.0",
                    strength="Strong",
                    mitre_id="T1566",
                    normalized_subject_or_target=m.rule,
                    claim_signature="malware_signature_match",
                    supporting_fact_ids=[yara_fact.id],
                    supporting_text=f"YARA Engine detected malicious signature: {m.rule}",
                    produced_by="yara_engine"
                ))
        except Exception as e:
            logger.error(f"YARA Engine failed: {e}")

        # Persist envelope metadata
        from_addr = canonical_email.from_addresses[0].address if canonical_email.from_addresses else None
        from_disp = canonical_email.from_addresses[0].display_name if canonical_email.from_addresses else None
        from_dom = (from_addr.split("@")[-1].lower() if from_addr and "@" in from_addr else None)
        reply_tos = [a.address for a in canonical_email.reply_to_addresses if a.address] if canonical_email.reply_to_addresses else []
        ret_path = canonical_email.return_path.address if (canonical_email.return_path and canonical_email.return_path.address) else None

        env_fact = FactModel(
            investigation_id=inv.id,
            analysis_run_id=run.id,
            fact_type="envelope_metadata",
            payload={
                "from_address": from_addr,
                "from_display": from_disp,
                "from_domain": from_dom,
                "reply_to": reply_tos,
                "return_path": ret_path,
                "subject": canonical_email.subject,
                "message_id": canonical_email.message_id,
                "date": canonical_email.date_raw,
            },
            produced_by="deterministic",
        )
        db.add(env_fact)

        # Persist received hops
        hops_list = [
            {
                "sequence_index": h.sequence_index,
                "from_claim": h.from_claim,
                "by_claim": h.by_claim,
                "observed_ip": h.observed_ip,
                "timestamp": h.timestamp_raw or (h.timestamp_parsed.isoformat() if h.timestamp_parsed else None),
                "tls": bool(h.with_claim and "ESMTPS" in h.with_claim.upper()),
                "raw_line": h.raw_line,
            }
            for h in canonical_email.received_chain_raw
        ]
        hops_fact = FactModel(
            investigation_id=inv.id,
            analysis_run_id=run.id,
            fact_type="received_hops",
            payload={"hops": hops_list},
            produced_by="deterministic",
        )
        db.add(hops_fact)

        # Persist extracted links
        links_list = [
            {
                "link_id": l.link_id,
                "href": l.href,
                "display_text": l.display_text,
                "source": l.source,
                "context_snippet": l.context_snippet,
            }
            for l in getattr(canonical_email.body, "links", []) or []
        ]
        links_fact = FactModel(
            investigation_id=inv.id,
            analysis_run_id=run.id,
            fact_type="extracted_links",
            payload={"links": links_list},
            produced_by="deterministic",
        )
        db.add(links_fact)

        # Persist extracted attachments
        att_list = [
            {
                "attachment_id": a.attachment_id,
                "filename": a.filename,
                "declared_mime_type": a.declared_mime_type,
                "size_bytes": a.size_bytes,
                "sha256": a.sha256,
                "content_disposition": a.content_disposition,
                "is_inline": a.is_inline,
            }
            for a in canonical_email.attachments
        ]
        att_fact = FactModel(
            investigation_id=inv.id,
            analysis_run_id=run.id,
            fact_type="extracted_attachments",
            payload={"attachments": att_list},
            produced_by="deterministic",
        )
        db.add(att_fact)

        # Persist user feedback context fact if run was triggered by feedback
        from app.models import UserFeedback
        fb = db.query(UserFeedback).filter(UserFeedback.resulting_analysis_run_id == run.id).first()
        if fb:
            fb_fact = FactModel(
                investigation_id=inv.id,
                analysis_run_id=run.id,
                fact_type="user_feedback_signal",
                payload={
                    "feedback_id": fb.id,
                    "feedback_type": fb.feedback_type,
                    "note": fb.note,
                    "source_run_id": fb.source_analysis_run_id,
                },
                produced_by="deterministic",
            )
            db.add(fb_fact)

        db.flush()

        # 6. Persist FindingCandidates as Findings

        from app.qualification_registry import get_qualification
        for out in all_outputs:
            for c in out.candidates:
                db_fact_ids = [fact_id_map.get(fid, fid) for fid in c.supporting_fact_ids]
                normalized_strength = c.strength.capitalize() if isinstance(c.strength, str) else str(c.strength)
                claim_sig = c.claim_signature
                q_entry = get_qualification(c.qualification_code)
                if q_entry is None:
                    logger.warning(f"Candidate rejected: unknown qualification_code '{c.qualification_code}' (no automatic remapping)")
                    continue
                if q_entry.allowed_claim_signatures and claim_sig not in q_entry.allowed_claim_signatures:
                    logger.warning(f"Candidate rejected: invalid claim_signature '{claim_sig}' for '{c.qualification_code}' (no automatic remapping)")
                    continue
                finding_payload = FindingCreate(
                    category=c.category,
                    qualification_code=c.qualification_code,
                    qualification_version=c.qualification_version,
                    strength=normalized_strength,
                    analysis_run_id=run.id,
                    normalized_subject_or_target=c.normalized_target or c.normalized_subject or "",
                    claim_signature=claim_sig,
                    supporting_fact_ids=db_fact_ids,
                    supporting_text=c.supporting_text or f"{c.category} finding {c.qualification_code}",
                    produced_by="deterministic",
                )
                persist_finding(db, user=user, investigation_id=inv.id, payload=finding_payload)

        # 6a. Laya Pre-Screen — fast (~35ms) typed decision pre-screening
        #     Advisory signals only: persisted as Facts, never as Findings.
        #     When benign + high confidence → optionally skip the expensive LLM call.
        from app.config import get_settings
        settings = get_settings()
        laya_prescreen_result = None

        if settings.laya_prescreen_enabled:
            try:
                from app.services.laya_prescreen import run_laya_prescreen

                # Extract sender address for Laya context
                laya_from = (
                    canonical_email.from_addresses[0].address
                    if canonical_email.from_addresses else None
                )

                laya_prescreen_result = run_laya_prescreen(
                    email_subject=email_subject,
                    email_body_text=email_body_text,
                    from_address=laya_from,
                    model_override=settings.laya_prescreen_model,
                    benign_confidence_threshold=settings.laya_prescreen_benign_confidence_threshold,
                    skip_ai_on_benign=settings.laya_prescreen_skip_ai_on_benign,
                )

                # Persist Laya pre-screen signals as an advisory Fact
                laya_fact = FactModel(
                    investigation_id=inv.id,
                    analysis_run_id=run.id,
                    fact_type="laya_prescreen",
                    payload=laya_prescreen_result.to_fact_payload(),
                    produced_by="laya_prescreen",
                )
                db.add(laya_fact)
                db.flush()

                # Record audit event for traceability
                record_audit_event(
                    db,
                    organization_id=user.organization_id,
                    action=AuditAction.LAYA_PRESCREEN_COMPLETED,
                    investigation_id=inv.id,
                    actor_user_id=user.id,
                    metadata={
                        "analysis_run_id": run.id,
                        "threat_category": laya_prescreen_result.threat_category,
                        "threat_category_confidence": laya_prescreen_result.threat_category_confidence,
                        "urgency_level": laya_prescreen_result.urgency_level,
                        "model_used": laya_prescreen_result.model_used,
                        "latency_ms": laya_prescreen_result.latency_ms,
                        "skip_ai_recommended": laya_prescreen_result.skip_ai_recommended,
                        "status": laya_prescreen_result.status,
                    },
                )

                logger.info(
                    f"Laya pre-screen persisted: category={laya_prescreen_result.threat_category}, "
                    f"skip_ai={laya_prescreen_result.skip_ai_recommended}"
                )
            except Exception as laya_exc:
                logger.warning(f"Laya pre-screen error (pipeline continues): {laya_exc}")
                laya_prescreen_result = None

        # 6b. Run AI Reasoner Pipeline with fault tolerance
        #     Respects Laya skip-AI recommendation when configured.
        from app.services.ai_reasoner_service import (
            run_ai_reasoning_pipeline,
            AI_STATUS_UNAVAILABLE,
            AI_STATUS_COMPLETED_NO_FINDINGS,
            AI_UNAVAILABLE_EXPLANATION,
            ERR_AI_UNAVAILABLE_RESOURCE_EXHAUSTED,
        )

        ai_result: Dict[str, Any] = {}

        # Check if Laya recommends skipping the AI Reasoner
        skip_ai_reasoner = (
            laya_prescreen_result is not None
            and laya_prescreen_result.status == "success"
            and laya_prescreen_result.skip_ai_recommended
        )

        if skip_ai_reasoner:
            logger.info(
                f"Skipping AI Reasoner: Laya pre-screen classified as "
                f"'{laya_prescreen_result.threat_category}' with confidence "
                f"{laya_prescreen_result.threat_category_confidence:.2f} "
                f"(threshold: {settings.laya_prescreen_benign_confidence_threshold})"
            )
            ai_result = {
                "ai_status": AI_STATUS_COMPLETED_NO_FINDINGS,
                "ai_error": None,
                "accepted_count": 0,
                "rejected_count": 0,
                "explanation": (
                    "AI content analysis bypassed: Laya pre-screen classified this email as "
                    f"'{laya_prescreen_result.threat_category}' with "
                    f"{laya_prescreen_result.threat_category_confidence:.0%} confidence. "
                    "Deterministic forensic analysis proceeds normally."
                ),
                "laya_skipped": True,
            }
        else:
            try:
                det_facts_for_hash = [
                    {
                        "key": f.key,
                        "state": getattr(f.state, "value", str(f.state)),
                        "value": f.value,
                        "detail": f.detail,
                    }
                    for out in all_outputs for f in out.facts
                ]
                ai_result = run_ai_reasoning_pipeline(
                    db,
                    user=user,
                    investigation_id=inv.id,
                    run_id=run.id,
                    email_subject=email_subject,
                    email_body_text=email_body_text,
                    source_fact_id=source_text_fact.id,
                    deterministic_facts=det_facts_for_hash,
                    simulated_failure=ai_simulated_failure,
                )
            except Exception as ai_exc:
                logger.warning(f"AI execution error (deterministic analysis continues): {ai_exc}")
                ai_result = {
                    "ai_status": AI_STATUS_UNAVAILABLE,
                    "ai_error": ERR_AI_UNAVAILABLE_RESOURCE_EXHAUSTED,
                    "explanation": AI_UNAVAILABLE_EXPLANATION,
                    "accepted_count": 0,
                    "rejected_count": 0,
                }

        # 7. Transition to SCORING
        transition_run_status(
            db, user=user, run_id=run.id,
            new_status=AnalysisRunStatus.SCORING,
            investigation_id=inv.id,
        )

        prov_extra = {
            "ai_status": ai_result.get("ai_status"),
            "ai_error": ai_result.get("ai_error"),
            "ai_accepted_count": ai_result.get("accepted_count", 0),
            "ai_rejected_count": ai_result.get("rejected_count", 0),
        }

        # Include Laya pre-screen metadata in provenance for traceability
        if laya_prescreen_result and laya_prescreen_result.status == "success":
            prov_extra["laya_prescreen"] = {
                "threat_category": laya_prescreen_result.threat_category,
                "threat_category_confidence": laya_prescreen_result.threat_category_confidence,
                "urgency_level": laya_prescreen_result.urgency_level,
                "model_used": laya_prescreen_result.model_used,
                "latency_ms": laya_prescreen_result.latency_ms,
                "skip_ai_recommended": laya_prescreen_result.skip_ai_recommended,
                "ai_skipped": ai_result.get("laya_skipped", False),
            }

        score = compute_and_persist_score(
            db,
            user=user,
            investigation_id=inv.id,
            run_id=run.id,
            provenance_extra=prov_extra,
        )

        # Step 2: Orchestration invokes Conclusion Generator separately
        # Score Engine is unaware of conclusion generation — this is the
        # strict separation boundary.
        from app.models import Finding as FindingModel
        run_findings = db.query(FindingModel).filter(
            FindingModel.investigation_id == inv.id,
            FindingModel.analysis_run_id == run.id,
        ).all()
        score = generate_and_persist_conclusion(
            db,
            user=user,
            score_conclusion=score,
            findings=run_findings,
            ai_status=ai_result.get("ai_status"),
        )

        # 8. Transition to COMPLETED
        transition_run_status(
            db, user=user, run_id=run.id,
            new_status=AnalysisRunStatus.COMPLETED,
            investigation_id=inv.id,
        )

        if inv.status == InvestigationStatus.AWAITING_ANALYSIS:
            from app.services.investigation_service import transition_status as transition_inv_status
            transition_inv_status(db, user=user, investigation_id=inv.id, new_status=InvestigationStatus.UNDER_REVIEW)
            
        # ZERO-TOUCH AUTO-REMEDIATION (Phase 9 Advanced Integration)
        if score.severity == 'CRITICAL':
            try:
                from app.services.enforcement_service import get_available_enforcement_options, request_enforcement, authorize_enforcement, execute_enforcement
                options = get_available_enforcement_options(db, user=user, investigation_id=inv.id)
                target_opt = next((o for o in options if o['action_type'] in ('BLOCK_IP', 'BLOCK_DOMAIN')), None)
                if target_opt:
                    logger.info(f'Auto-remediating CRITICAL threat: {target_opt["action_type"]} -> {target_opt["target"]}')
                    req = request_enforcement(db, user=user, investigation_id=inv.id, action_type=target_opt['action_type'], target=target_opt['target'], note='Auto-remediated by Zero-Touch engine due to CRITICAL score.')
                    auth = authorize_enforcement(db, user=user, investigation_id=inv.id, action_id=req.id)
                    execute_enforcement(db, user=user, investigation_id=inv.id, action_id=req.id, simulate_failure=False)
            except Exception as auto_exc:
                logger.error(f'Auto-remediation failed: {auto_exc}')
        db.commit()

        return {
            "investigation_id": inv.id,
            "artifact_id": artifact.id,
            "analysis_run_id": run.id,
            "total_score": score.total_score,
            "severity": score.severity,
            "triggered_floor_codes": score.triggered_floor_codes,
            "ai_status": ai_result.get("ai_status"),
            "ai_error": ai_result.get("ai_error"),
            "ai_skipped_by_laya": ai_result.get("laya_skipped", False),
            "laya_prescreen": (
                laya_prescreen_result.to_fact_payload()
                if laya_prescreen_result and laya_prescreen_result.status == "success"
                else None
            ),
            "status": "COMPLETED",
        }

    except Exception as exc:
        db.rollback()
        logger.exception(f"Analysis pipeline failed for run {run_id}: {exc}")
        try:
            transition_run_status(
                db, user=user, run_id=run.id,
                new_status=AnalysisRunStatus.FAILED,
                failure_reason=str(exc),
                investigation_id=inv.id,
            )
        except Exception as trans_exc:
            logger.error(f"Failed to transition run to FAILED: {trans_exc}")
        raise exc
