from datetime import datetime, timezone
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

import json
from app.audit import record_audit_event
from app.models import (
    Investigation,
    InvestigationStatus,
    AuditAction,
    User,
    UserRole,
    AnalysisRun,
    ScoreConclusion,
    Finding,
    Fact,
    Artifact,
    AuditEvent,
)
from app.security import assert_same_org

# Allowed forward transitions. "Reopen" is handled separately below and
# is the only way back to UNDER_REVIEW from a terminal-ish state.
_ALLOWED_TRANSITIONS: dict[InvestigationStatus, set[InvestigationStatus]] = {
    InvestigationStatus.AWAITING_ANALYSIS: {InvestigationStatus.UNDER_REVIEW},
    InvestigationStatus.UNDER_REVIEW: {
        InvestigationStatus.CONFIRMED,
        InvestigationStatus.FALSE_POSITIVE,
        InvestigationStatus.ESCALATED,
        InvestigationStatus.CLOSED,
    },
    InvestigationStatus.CONFIRMED: {InvestigationStatus.CLOSED},
    InvestigationStatus.FALSE_POSITIVE: {InvestigationStatus.CLOSED},
    InvestigationStatus.ESCALATED: {InvestigationStatus.CLOSED},
    InvestigationStatus.CLOSED: set(),
}


def create_investigation(db: Session, *, user: User, title: str) -> Investigation:
    inv = Investigation(
        organization_id=user.organization_id,
        title=title,
        status=InvestigationStatus.AWAITING_ANALYSIS,
        created_by_user_id=user.id,
    )
    db.add(inv)
    db.flush()
    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.INVESTIGATION_CREATED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={"title": title},
    )
    db.commit()
    db.refresh(inv)
    return inv


def _populate_investigation_computed_fields(db: Session, inv: Investigation) -> None:
    if inv.current_analysis_run_id:
        inv.current_run_status = "COMPLETED"
        score_row = db.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == inv.current_analysis_run_id).first()
        if score_row:
            inv.score = score_row.total_score
            inv.severity = score_row.severity
            inv.verdict = score_row.verdict
    else:
        latest_run = (
            db.query(AnalysisRun)
            .filter(AnalysisRun.investigation_id == inv.id)
            .order_by(AnalysisRun.created_at.desc())
            .first()
        )
        if latest_run:
            inv.current_run_status = latest_run.status.value
        else:
            inv.current_run_status = None


def get_investigation(db: Session, *, user: User, investigation_id: str) -> Investigation:
    inv = db.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    assert_same_org(user, inv.organization_id)
    
    if user.role == UserRole.USER and inv.created_by_user_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You can only view your own investigations.")
        
    _populate_investigation_computed_fields(db, inv)
    return inv


def list_investigations(db: Session, *, user: User) -> list[Investigation]:
    query = db.query(Investigation).filter(Investigation.organization_id == user.organization_id)
    
    if user.role == UserRole.USER:
        query = query.filter(Investigation.created_by_user_id == user.id)
        
    invs = query.order_by(Investigation.created_at.desc()).all()
    for inv in invs:
        _populate_investigation_computed_fields(db, inv)
    return invs


def transition_status(
    db: Session, *, user: User, investigation_id: str, new_status: InvestigationStatus
) -> Investigation:
    inv = get_investigation(db, user=user, investigation_id=investigation_id)

    # Server-side role enforcement: regular users / viewers cannot transition to analyst terminal states
    if new_status in (
        InvestigationStatus.CONFIRMED,
        InvestigationStatus.FALSE_POSITIVE,
        InvestigationStatus.ESCALATED,
    ) and user.role not in (UserRole.ANALYST, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{user.role.value if hasattr(user.role, 'value') else user.role}' is not authorized to transition to {new_status.value}",
        )

    if new_status == InvestigationStatus.UNDER_REVIEW and inv.status in (
        InvestigationStatus.CONFIRMED,
        InvestigationStatus.FALSE_POSITIVE,
        InvestigationStatus.ESCALATED,
        InvestigationStatus.CLOSED,
    ):
        return reopen_investigation(db, user=user, investigation_id=investigation_id)

    allowed = _ALLOWED_TRANSITIONS.get(inv.status, set())
    if new_status not in allowed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot transition investigation from {inv.status.value} to {new_status.value}",
        )

    old_status = inv.status
    inv.status = new_status
    db.flush()
    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.INVESTIGATION_STATUS_CHANGED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={"from": old_status.value, "to": new_status.value},
    )
    db.commit()
    db.refresh(inv)
    return inv


def reopen_investigation(db: Session, *, user: User, investigation_id: str) -> Investigation:
    """
    Reopening is an ACTION, not a status value. It always lands the
    investigation back in UNDER_REVIEW, regardless of which terminal-ish
    status it was in. There is no REOPENED status in the schema.
    """
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    if user.role not in (UserRole.ANALYST, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{user.role.value if hasattr(user.role, 'value') else user.role}' is not authorized to reopen investigations",
        )

    if inv.status not in (
        InvestigationStatus.CONFIRMED,
        InvestigationStatus.FALSE_POSITIVE,
        InvestigationStatus.ESCALATED,
        InvestigationStatus.CLOSED,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot reopen an investigation in status {inv.status.value}",
        )

    old_status = inv.status
    inv.status = InvestigationStatus.UNDER_REVIEW
    db.flush()
    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.INVESTIGATION_REOPENED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={"from": old_status.value, "to": InvestigationStatus.UNDER_REVIEW.value},
    )
    db.commit()
    db.refresh(inv)
    return inv


CANONICAL_ANALYST_ACTIONS = {
    "confirm_malicious",
    "false_positive",
    "needs_escalation",
    "add_note",
    "reopen",
    "close",
}


def record_analyst_action(
    db: Session,
    *,
    user: User,
    investigation_id: str,
    action: str,
    note: str | None = None,
    false_positive_reason: str | None = None,
) -> dict:
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    raw_action = action.strip() if action else ""

    # Reject legacy aliases and unapproved actions
    if raw_action not in CANONICAL_ANALYST_ACTIONS:
        legacy_set = {"confirm", "confirm_malicious_legacy", "mark_false_positive", "escalate", "note"}
        if raw_action.lower() in legacy_set or raw_action in ("CONFIRM", "CONFIRM_MALICIOUS", "MARK_FALSE_POSITIVE", "ESCALATE", "NOTE"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"Legacy alias '{action}' is rejected. Canonical analyst actions are: "
                    f"{sorted(list(CANONICAL_ANALYST_ACTIONS))}"
                ),
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown analyst action: '{action}'. Canonical actions are: {sorted(list(CANONICAL_ANALYST_ACTIONS))}",
        )

    # Action 1: ADD_NOTE (allowed for authenticated users in the organization)
    # Does NOT change investigation status; emits NOTE_ADDED audit event
    if raw_action == "add_note":
        ev = record_audit_event(
            db,
            organization_id=user.organization_id,
            action=AuditAction.NOTE_ADDED,
            investigation_id=inv.id,
            actor_user_id=user.id,
            metadata={"action": "add_note", "note": note},
        )
        db.commit()
        ev_id = ev.id if ev else inv.id
        return {
            "actionId": f"action-{ev_id}",
            "action": "add_note",
            "actor": user.email,
            "note": note,
            "falsePositiveReason": None,
            "timestamp": ev.created_at.isoformat() if ev else datetime.now(timezone.utc).isoformat(),
        }

    # All state-changing actions require ANALYST or ADMIN role:
    # confirm_malicious, false_positive, needs_escalation, reopen, close
    if user.role not in (UserRole.ANALYST, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{user.role.value if hasattr(user.role, 'value') else user.role}' is not authorized to perform analyst action '{action}'",
        )

    # Action 2: REOPEN
    if raw_action == "reopen":
        reopen_investigation(db, user=user, investigation_id=investigation_id)
        ev = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.investigation_id == inv.id,
                AuditEvent.action == AuditAction.INVESTIGATION_REOPENED,
            )
            .order_by(AuditEvent.created_at.desc())
            .first()
        )
        if ev:
            meta = dict(ev.metadata_json or {})
            meta["action"] = "reopen"
            if note:
                meta["note"] = note
            if false_positive_reason:
                meta["falsePositiveReason"] = false_positive_reason
            ev.metadata_json = meta
            db.flush()
            db.commit()
        ev_id = ev.id if ev else inv.id
        return {
            "actionId": f"action-{ev_id}",
            "action": "reopen",
            "actor": user.email,
            "note": note,
            "falsePositiveReason": false_positive_reason,
            "timestamp": ev.created_at.isoformat() if ev else datetime.now(timezone.utc).isoformat(),
        }

    # Action 3: FALSE_POSITIVE requires rationale
    if raw_action == "false_positive":
        rationale = false_positive_reason or (note.strip() if note else "")
        if not rationale:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Action 'false_positive' requires a rationale (note or false_positive_reason).",
            )

    action_target_map = {
        "confirm_malicious": InvestigationStatus.CONFIRMED,
        "false_positive": InvestigationStatus.FALSE_POSITIVE,
        "needs_escalation": InvestigationStatus.ESCALATED,
        "close": InvestigationStatus.CLOSED,
    }

    target_status = action_target_map.get(raw_action)
    allowed = _ALLOWED_TRANSITIONS.get(inv.status, set())
    if target_status not in allowed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot transition investigation from {inv.status.value} to {target_status.value}",
        )

    old_status = inv.status
    inv.status = target_status
    db.flush()

    meta = {
        "action": raw_action,
        "from": old_status.value,
        "to": target_status.value,
    }
    if note:
        meta["note"] = note
    if false_positive_reason:
        meta["falsePositiveReason"] = false_positive_reason

    ev = record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.INVESTIGATION_STATUS_CHANGED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata=meta,
    )
    db.commit()
    db.refresh(inv)

    ev_id = ev.id if ev else inv.id

    return {
        "actionId": f"action-{ev_id}",
        "action": raw_action,
        "actor": user.email,
        "note": note,
        "falsePositiveReason": false_positive_reason,
        "timestamp": ev.created_at.isoformat() if ev else datetime.now(timezone.utc).isoformat(),
    }


def get_investigation_audit_events(db: Session, *, user: User, investigation_id: str) -> list[AuditEvent]:
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    return (
        db.query(AuditEvent)
        .filter(AuditEvent.investigation_id == inv.id)
        .order_by(AuditEvent.created_at.asc())
        .all()
    )


def classify_audit_action_type(e: AuditEvent) -> str:
    """
    Maps AuditAction + metadata to frontend AuditEntry.type:
    'ingestion' | 'analysis' | 'review' | 'confirmation' | 'note' | 'escalation' | 'export' | 'reopen' | 'close'
    """
    act = e.action.value if hasattr(e.action, "value") else str(e.action)
    meta = e.metadata_json or {}
    if act == "NOTE_ADDED":
        return "note"
    if act == "INVESTIGATION_REOPENED":
        return "reopen"
    if act == "EVIDENCE_EXPORTED":
        return "export"
    if act in ("ARTIFACT_INGESTED", "INVESTIGATION_CREATED"):
        return "ingestion"
    if act == "INVESTIGATION_STATUS_CHANGED":
        to_status = (meta.get("to") or "").upper()
        if to_status == "CONFIRMED":
            return "confirmation"
        if to_status == "ESCALATED":
            return "escalation"
        if to_status == "CLOSED":
            return "close"
        return "review"
    if any(k in act for k in ("ANALYSIS", "FINDING", "SCORE", "AI_")):
        return "analysis"
    return "review"


def get_investigation_full_detail(db: Session, *, user: User, investigation_id: str) -> dict:
    """
    Composes full InvestigationDetail matching frontend API contract:
    includes runs, currentRun, result (score, findings, evidence facts),
    audit trail, and export bundle status.
    """
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    runs = (
        db.query(AnalysisRun)
        .filter(AnalysisRun.investigation_id == inv.id)
        .order_by(AnalysisRun.created_at.asc())
        .all()
    )
    current_run = None
    if inv.current_analysis_run_id:
        current_run = db.get(AnalysisRun, inv.current_analysis_run_id)

    findings = (
        db.query(Finding)
        .filter(Finding.investigation_id == inv.id)
        .all()
    )
    facts = (
        db.query(Fact)
        .filter(Fact.investigation_id == inv.id)
        .all()
    )
    artifact = (
        db.query(Artifact)
        .filter(Artifact.investigation_id == inv.id)
        .order_by(Artifact.ingested_at.desc())
        .first()
    )
    audit_events = (
        db.query(AuditEvent)
        .filter(AuditEvent.investigation_id == inv.id)
        .order_by(AuditEvent.created_at.asc())
        .all()
    )

    composed_runs = []
    current_run_composed = None

    for r in runs:
        score_row = db.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == r.id).one_or_none()
        run_result = None
        if score_row:
            prob_ip = None
            for f in facts:
                if f.analysis_run_id == r.id and f.fact_type in ("hop0_candidate_ip", "candidate_probable_origin_ip"):
                    val = (f.payload or {}).get("value")
                    if val and (f.payload or {}).get("state") in ("present", None):
                        prob_ip = val
                        break

            hops_data = []
            links_data = []
            attachments_data = []
            env_metadata = {}
            for f in facts:
                if f.analysis_run_id == r.id:
                    p = f.payload or {}
                    if f.fact_type == "received_hops":
                        raw_hops = p.get("hops", [])
                        for h in raw_hops:
                            hops_data.append({
                                "hopIndex": h.get("sequence_index", 0),
                                "receivingServer": h.get("by_claim"),
                                "observedIp": h.get("observed_ip"),
                                "timestamp": h.get("timestamp"),
                                "trustStatus": "unknown"
                            })
                    elif f.fact_type == "extracted_links":
                        raw_links = p.get("links", [])
                        for l in raw_links:
                            import urllib.parse
                            domain = urllib.parse.urlparse(l.get("href", "")).netloc if l.get("href") else "unknown"
                            links_data.append({
                                "visibleText": l.get("display_text") or l.get("href", ""),
                                "actualHref": l.get("href", ""),
                                "actualDomain": domain,
                                "suspiciousIndicators": [],
                                "blocklistMatch": "unavailable"
                            })
                    elif f.fact_type == "extracted_attachments":
                        raw_atts = p.get("attachments", [])
                        for a in raw_atts:
                            attachments_data.append({
                                "filename": a.get("filename") or "unknown",
                                "mimeType": a.get("declared_mime_type") or "application/octet-stream",
                                "sizeBytes": a.get("size_bytes") or 0,
                                "sha256": a.get("sha256") or "unknown",
                                "suspiciousIndicators": [],
                                "archiveStatus": "unavailable"
                            })
                    elif f.fact_type == "envelope_metadata":
                        env_metadata = p

            routing_info = {
                "hops": hops_data,
                "candidateProbableOriginIp": prob_ip,
                "candidateOriginConfidence": "candidate" if prob_ip else None,
                "anomalies": [
                    (f.payload or {}).get("detail", "")
                    for f in facts
                    if f.analysis_run_id == r.id and "contradiction" in (f.fact_type or "")
                ],
            }

            auth_info = {
                "spf": {"result": "unavailable", "explanation": "SPF not evaluated", "technicalDetails": ""},
                "dkim": {"result": "unavailable", "explanation": "DKIM not evaluated", "technicalDetails": ""},
                "dmarc": {"result": "unavailable", "explanation": "DMARC not evaluated", "technicalDetails": ""},
                "alignment": {"result": "unavailable", "explanation": "Alignment not evaluated", "technicalDetails": ""},
            }
            for f in facts:
                if f.analysis_run_id == r.id:
                    ft = (f.fact_type or "").lower()
                    p = f.payload or {}
                    val = p.get("value")
                    det = p.get("detail", "")
                    if ft == "spf_result":
                        auth_info["spf"] = {"result": str(val or "unavailable").lower(), "explanation": det or f"SPF {val}", "technicalDetails": det}
                    elif ft == "dkim_result":
                        auth_info["dkim"] = {"result": str(val or "unavailable").lower(), "explanation": det or f"DKIM {val}", "technicalDetails": det}
                    elif ft == "dmarc_result":
                        auth_info["dmarc"] = {"result": str(val or "unavailable").lower(), "explanation": det or f"DMARC {val}", "technicalDetails": det}
                    elif ft == "identifier_alignment":
                        auth_info["alignment"] = {"result": str(val or "unavailable").lower(), "explanation": det or f"Alignment {val}", "technicalDetails": det}

            from_str = env_metadata.get("from_address")
            disp_name = env_metadata.get("from_display")
            rt_list = env_metadata.get("reply_to")
            reply_to_str = ", ".join(rt_list) if isinstance(rt_list, list) and rt_list else (rt_list if isinstance(rt_list, str) else None)
            rp_str = env_metadata.get("return_path")
            mismatches = []

            for f in facts:
                if f.analysis_run_id == r.id:
                    p = f.payload or {}
                    if f.fact_type == "reply_to_mismatch" and p.get("state") == "present":
                        mismatches.append(p.get("detail", "Reply-To mismatch"))
                        if not reply_to_str:
                            reply_to_str = p.get("value")
                    elif f.fact_type == "return_path_mismatch" and p.get("state") == "present":
                        mismatches.append(p.get("detail", "Return-Path mismatch"))
                        if not rp_str:
                            rp_str = p.get("value")
                    elif f.fact_type == "display_name_mismatch" and p.get("state") == "present":
                        if not disp_name:
                            disp_name = p.get("value")

            identity_info = {
                "from": from_str,
                "displayName": disp_name,
                "replyTo": reply_to_str,
                "returnPath": rp_str,
                "mismatches": mismatches,
                "impersonationEvidence": [f.supporting_text for f in findings if f.category == "Identity" and f.analysis_run_id == r.id],
            }

            brand_target = next(
                (f.normalized_subject_or_target for f in findings if f.analysis_run_id == r.id and f.qualification_code == "PROTECTED_BRAND_LOOKALIKE_DOMAIN"),
                None,
            )
            sender_domain = env_metadata.get("from_domain")
            if not sender_domain and from_str and "@" in from_str:
                sender_domain = from_str.split("@")[-1]

            dom_info = {
                "senderDomain": sender_domain,
                "domainAgeDays": None,
                "protectedBrandMatch": brand_target,
                "isPunycode": any(f.analysis_run_id == r.id and f.fact_type == "punycode_domain" and (f.payload or {}).get("state") == "present" for f in facts),
                "homoglyphIndicators": [f.supporting_text for f in findings if f.category == "Domain" and f.analysis_run_id == r.id],
            }

            findings_pres = [
                {
                    "analysis_run_id": f.analysis_run_id,
                    "category": f.category,
                    "qualification_code": f.qualification_code,
                    "qualification_version": f.qualification_version,
                    "strength": f.strength,
                    "normalized_subject": f.normalized_subject_or_target,
                    "normalized_target": f.normalized_subject_or_target,
                    "claim_signature": f.claim_signature,
                    "supporting_fact_ids": f.supporting_fact_ids or [],
                    "supporting_text": f.supporting_text,
                    "produced_by": f.produced_by,
                    "display_label": f"{f.category}: {f.qualification_code} ({f.strength})",
                }
                for f in findings if f.analysis_run_id == r.id
            ]

            evidence_facts = [
                {
                    "factId": f.id,
                    "description": (f.payload or {}).get("detail") or f.fact_type,
                    "source": f.produced_by,
                }
                for f in facts if f.analysis_run_id == r.id
            ]

            verdict = score_row.verdict
            one_line = score_row.one_line_explanation or f"{str(verdict).replace('_', ' ').title()}: {score_row.severity} risk score {score_row.total_score}/100"
            why_exp = score_row.why_explanation or score_row.conclusion_text

            run_result = {
                "score": score_row.total_score,
                "total_score": score_row.total_score,
                "severity": score_row.severity.lower(),
                "verdict": verdict,
                "triggered_floor_codes": score_row.triggered_floor_codes or [],
                "conclusion": {
                    "oneLineExplanation": one_line,
                    "whyExplanation": why_exp,
                },
                "routing": routing_info,
                "authentication": auth_info,
                "identity": identity_info,
                "domain": dom_info,
                "links": links_data,
                "attachments": attachments_data,
                "findings": findings_pres,
                "evidenceFacts": evidence_facts,
            }

        run_dict = {
            "runId": r.id,
            "status": r.status.value,
            "startedAt": r.started_at.isoformat() if r.started_at else r.created_at.isoformat(),
            "completedAt": r.completed_at.isoformat() if r.completed_at else None,
            "result": run_result,
            "failureReason": r.failure_reason,
        }
        composed_runs.append(run_dict)
        if current_run and r.id == current_run.id:
            current_run_composed = run_dict

    if current_run_composed is None:
        if composed_runs:
            latest_run_dict = composed_runs[-1]
            current_run_composed = {
                "runId": latest_run_dict["runId"],
                "status": latest_run_dict["status"],
                "startedAt": latest_run_dict["startedAt"],
                "completedAt": latest_run_dict["completedAt"],
                "result": None,
                "failureReason": latest_run_dict["failureReason"],
            }
        else:
            current_run_composed = {
                "runId": "none",
                "status": "QUEUED",
                "startedAt": inv.created_at.isoformat(),
                "completedAt": None,
                "result": None,
                "failureReason": None,
            }

    audit_entries = [
        {
            "entryId": e.id,
            "type": classify_audit_action_type(e),
            "actor": e.actor_user_id,
            "timestamp": e.created_at.isoformat(),
            "detail": f"{e.action.value}: {json.dumps(e.metadata_json or {})}",
        }
        for e in audit_events
    ]

    analyst_actions = []
    for e in audit_events:
        if e.action in (AuditAction.INVESTIGATION_STATUS_CHANGED, AuditAction.INVESTIGATION_REOPENED, AuditAction.NOTE_ADDED):
            meta = e.metadata_json or {}
            action_name = meta.get("action")
            if not action_name:
                if e.action == AuditAction.INVESTIGATION_REOPENED:
                    action_name = "REOPEN"
                elif e.action == AuditAction.NOTE_ADDED:
                    action_name = "add_note"
                elif meta.get("to") in ("CONFIRMED", "FALSE_POSITIVE", "ESCALATED", "CLOSED"):
                    action_name = meta.get("to")
            if action_name:
                analyst_actions.append({
                    "actionId": f"action-{e.id}",
                    "action": action_name,
                    "actor": e.actor_user_id or "analyst",
                    "note": meta.get("note"),
                    "falsePositiveReason": meta.get("falsePositiveReason"),
                    "timestamp": e.created_at.isoformat(),
                })

    export_info = {
        "original_artifact_sha256": artifact.original_artifact_sha256 if artifact else "",
        "export_bundle_sha256": artifact.export_bundle_sha256 if artifact else None,
        "investigationId": inv.id,
        "analysisVersion": "1.0.0",
        "packageStatus": "ready" if (artifact and artifact.export_bundle_sha256) else "not_generated",
    }

    return {
        "investigationId": inv.id,
        "createdAt": inv.created_at.isoformat(),
        "status": inv.status.value,
        "runs": composed_runs,
        "currentRun": current_run_composed,
        "auditTrail": audit_entries,
        "analystActions": analyst_actions,
        "evidenceExport": export_info,
    }
