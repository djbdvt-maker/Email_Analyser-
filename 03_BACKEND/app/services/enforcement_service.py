"""
Threat Response & Enforcement Service.
=====================================
Manages the lifecycle of security enforcement actions (BLOCK_SENDER, BLOCK_DOMAIN,
BLOCK_IP, QUARANTINE) with:
1. Strict target normalization (sender, domain, IP).
2. Grounding verification (rejects arbitrary target injection not grounded in investigation evidence).
3. RBAC checks (analyst/admin required for authorization/execution; AI cannot authorize).
4. Explicit lifecycle states: REQUESTED -> AUTHORIZED -> EXECUTED (or FAILED / REJECTED).
5. Immutable, auditable event trail for all enforcement transitions.
6. Integration with provider-neutral enforcement abstraction.
"""
import ipaddress
import re
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Set

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.models import (
    EnforcementAction,
    EnforcementActionType,
    EnforcementStatus,
    Investigation,
    Fact,
    Finding,
    User,
    UserRole,
    AuditAction,
)
from app.services.enforcement_provider import get_default_enforcement_provider
from app.interfaces.enforcement import EnforcementProvider
from app.services.investigation_service import get_investigation


# --------------------------------------------------------------------------
# Normalization & Validation
# --------------------------------------------------------------------------

_EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
_DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")


def normalize_sender(raw_sender: str) -> str:
    cleaned = (raw_sender or "").strip().lower()
    # Handle "<user@domain.com>" syntax if present
    if "<" in cleaned and ">" in cleaned:
        start = cleaned.find("<") + 1
        end = cleaned.find(">")
        cleaned = cleaned[start:end].strip()
    if not cleaned or not _EMAIL_REGEX.match(cleaned):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid sender email address format: '{raw_sender}'",
        )
    return cleaned


def normalize_domain(raw_domain: str) -> str:
    cleaned = (raw_domain or "").strip().lower().rstrip(".")
    # Strip protocol prefix if accidentally included
    if "://" in cleaned:
        cleaned = cleaned.split("://")[-1].split("/")[0]
    cleaned = cleaned.split(":")[0]  # remove port if present
    if not cleaned or not _DOMAIN_REGEX.match(cleaned):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain name format: '{raw_domain}'",
        )
    return cleaned


def normalize_ip(raw_ip: str) -> str:
    cleaned = (raw_ip or "").strip()
    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid IP address format: '{raw_ip}'",
        )

    # Reject unsupported/unsafe IP targets: unspecified, loopback, link-local, multicast, private RFC1918
    if ip_obj.is_unspecified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported IP target: 0.0.0.0 / unspecified address cannot be blocked.",
        )
    if ip_obj.is_loopback:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported IP target: loopback addresses cannot be blocked.",
        )
    if ip_obj.is_link_local:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported IP target: link-local addresses cannot be blocked.",
        )
    if ip_obj.is_multicast:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported IP target: multicast addresses cannot be blocked.",
        )
    if ip_obj.is_private:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported IP target: private / RFC 1918 addresses cannot be blocked via threat response.",
        )

    return str(ip_obj)


def normalize_target(action_type: str, raw_target: str) -> str:
    act = action_type.upper()
    if act == "BLOCK_SENDER":
        return normalize_sender(raw_target)
    elif act == "BLOCK_DOMAIN":
        return normalize_domain(raw_target)
    elif act == "BLOCK_IP":
        return normalize_ip(raw_target)
    elif act == "QUARANTINE":
        # Target for quarantine can be message-id, artifact-id, or subject string
        cleaned = (raw_target or "").strip()
        if not cleaned:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Quarantine target cannot be empty.",
            )
        return cleaned
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown enforcement action type: '{action_type}'",
        )


# --------------------------------------------------------------------------
# Evidence Grounding
# --------------------------------------------------------------------------

def get_grounded_evidence_targets(db: Session, inv: Investigation) -> Dict[str, Dict[str, Any]]:
    """
    Extracts all grounded senders, domains, and IPs observed in the investigation's
    CURRENT analysis run's deterministic facts and findings, retaining provenance.
    """
    investigation_id = inv.id
    current_run_id = inv.current_analysis_run_id

    # Format: dict mapping normalized target to its context: {"fact_ids": set(), "finding_ids": set()}
    senders: Dict[str, Dict[str, set]] = {}
    domains: Dict[str, Dict[str, set]] = {}
    ips: Dict[str, Dict[str, set]] = {}
    quarantine_targets: Dict[str, Dict[str, set]] = {
        investigation_id: {"fact_ids": set(), "finding_ids": set()}
    }

    def _add_target(mapping: Dict[str, Dict[str, set]], target: str, fact_id: str = None, finding_id: str = None):
        if target not in mapping:
            mapping[target] = {"fact_ids": set(), "finding_ids": set()}
        if fact_id:
            mapping[target]["fact_ids"].add(fact_id)
        if finding_id:
            mapping[target]["finding_ids"].add(finding_id)

    if not current_run_id:
        return {"senders": senders, "domains": domains, "ips": ips, "quarantine": quarantine_targets}

    # 1. Inspect facts from the CURRENT run only
    facts = db.query(Fact).filter(Fact.investigation_id == investigation_id, Fact.analysis_run_id == current_run_id).all()
    for f in facts:
        p = f.payload or {}
        fid = f.id
        if f.fact_type == "envelope_metadata":
            from_addr = p.get("from_address")
            if from_addr:
                try:
                    _add_target(senders, normalize_sender(from_addr), fact_id=fid)
                except Exception:
                    pass
            from_dom = p.get("from_domain")
            if from_dom:
                try:
                    _add_target(domains, normalize_domain(from_dom), fact_id=fid)
                except Exception:
                    pass
            reply_tos = p.get("reply_to") or []
            for r in reply_tos:
                try:
                    _add_target(senders, normalize_sender(r), fact_id=fid)
                    if "@" in r:
                        _add_target(domains, normalize_domain(r.split("@")[-1]), fact_id=fid)
                except Exception:
                    pass
            msg_id = p.get("message_id")
            if msg_id:
                _add_target(quarantine_targets, msg_id, fact_id=fid)

        if f.fact_type in ("probable_origin_ip", "grounded_infrastructure_ip"):
            val = p.get("value") or p.get("ip")
            if val:
                try:
                    ip_obj = ipaddress.ip_address(val)
                    if ip_obj.is_global and not ip_obj.is_multicast:
                        _add_target(ips, val, fact_id=fid)
                except ValueError:
                    pass

        if f.fact_type == "received_hops":
            hops = p.get("hops") or []
            for h in hops:
                from_c = h.get("from_claim")
                if from_c:
                    try:
                        _add_target(domains, normalize_domain(from_c), fact_id=fid)
                    except Exception:
                        pass

        if f.fact_type == "extracted_links":
            links = p.get("links") or []
            for l in links:
                href = l.get("href") or ""
                if "://" in href:
                    dom = href.split("://")[-1].split("/")[0].split(":")[0]
                    try:
                        _add_target(domains, normalize_domain(dom), fact_id=fid)
                    except Exception:
                        pass

    # 2. Inspect findings from the CURRENT run only
    findings = db.query(Finding).filter(Finding.investigation_id == investigation_id, Finding.analysis_run_id == current_run_id).all()
    for fd in findings:
        subj = fd.normalized_subject_or_target or ""
        fid = fd.id
        if "@" in subj:
            try:
                _add_target(senders, normalize_sender(subj), finding_id=fid)
                _add_target(domains, normalize_domain(subj.split("@")[-1]), finding_id=fid)
            except Exception:
                pass
        elif "." in subj and not subj.startswith("."):
            try:
                _add_target(domains, normalize_domain(subj), finding_id=fid)
            except Exception:
                pass

    return {
        "senders": senders,
        "domains": domains,
        "ips": ips,
        "quarantine": quarantine_targets,
    }


def validate_target_grounded(
    db: Session, inv: Investigation, action_type: str, normalized_target: str
) -> Dict[str, set]:
    """
    Guarantees that an enforcement target is strictly grounded in the investigation's
    forensic evidence. Rejects arbitrary target injection (e.g. user entering random IPs).
    Returns the provenance context (finding_ids, fact_ids) for this target.
    """
    grounded = get_grounded_evidence_targets(db, inv)
    act = action_type.upper()
    ctx = None

    if act == "BLOCK_SENDER":
        ctx = grounded["senders"].get(normalized_target)
        if ctx is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Sender '{normalized_target}' is not grounded in this investigation's evidence. Arbitrary sender cannot be blocked.",
            )
    elif act == "BLOCK_DOMAIN":
        ctx = grounded["domains"].get(normalized_target)
        if ctx is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Domain '{normalized_target}' is not grounded in this investigation's evidence. Arbitrary domain cannot be blocked.",
            )
    elif act == "BLOCK_IP":
        ctx = grounded["ips"].get(normalized_target)
        if ctx is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"IP address '{normalized_target}' is not grounded in this investigation's transmission facts. Arbitrary IP cannot be blocked.",
            )
    elif act == "QUARANTINE":
        ctx = grounded["quarantine"].get(normalized_target)
        if ctx is None and normalized_target == inv.id:
            ctx = {"fact_ids": set(), "finding_ids": set()}
        if ctx is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Quarantine target '{normalized_target}' is not grounded in this investigation.",
            )
    
    return ctx


# --------------------------------------------------------------------------
# RBAC Checks
# --------------------------------------------------------------------------

def require_analyst_or_admin(user: User) -> None:
    """Enforces that only ANALYST and ADMIN roles can authorize or execute enforcement."""
    if user.role not in (UserRole.ANALYST, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Enforcement authorization and execution requires ANALYST or ADMIN role.",
        )


# --------------------------------------------------------------------------
# Enforcement Operations
# --------------------------------------------------------------------------

def get_available_enforcement_options(db: Session, *, user: User, investigation_id: str) -> List[Dict[str, str]]:
    """Lists available grounded enforcement targets for this investigation."""
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    grounded = get_grounded_evidence_targets(db, inv)

    options = []
    for s in sorted(grounded["senders"].keys()):
        options.append({
            "action_type": "BLOCK_SENDER",
            "target": s,
            "grounded_source": "envelope_metadata / sender address",
            "description": f"Block sender address {s}",
        })
    for d in sorted(grounded["domains"].keys()):
        options.append({
            "action_type": "BLOCK_DOMAIN",
            "target": d,
            "grounded_source": "envelope_metadata / links / finding targets",
            "description": f"Block domain {d}",
        })
    for ip in sorted(grounded["ips"].keys()):
        options.append({
            "action_type": "BLOCK_IP",
            "target": ip,
            "grounded_source": "probable_origin_ip / grounded infrastructure",
            "description": f"Block infrastructure IP {ip}",
        })
    options.append({
        "action_type": "QUARANTINE",
        "target": inv.id,
        "grounded_source": "investigation artifact",
        "description": f"Quarantine investigation message artifact {inv.id}",
    })

    return options


def request_enforcement(
    db: Session,
    *,
    user: User,
    investigation_id: str,
    action_type: str,
    target: str,
    context: Optional[Dict[str, Any]] = None,
) -> EnforcementAction:
    """Creates a new enforcement action in REQUESTED state."""
    inv = get_investigation(db, user=user, investigation_id=investigation_id)

    # 1. Normalize target
    norm_target = normalize_target(action_type, target)

    # 2. Verify grounding and get provenance
    prov_ctx = validate_target_grounded(db, inv, action_type, norm_target)

    # Map enum
    try:
        act_enum = EnforcementActionType(action_type.upper())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid action_type: {action_type}",
        )
    
    exec_details = {
        "requested_context": context or {},
        "grounding_provenance": {
            "analysis_run_id": inv.current_analysis_run_id,
            "fact_ids": list(prov_ctx["fact_ids"]),
            "finding_ids": list(prov_ctx["finding_ids"]),
        }
    }

    action = EnforcementAction(
        organization_id=user.organization_id,
        investigation_id=inv.id,
        action_type=act_enum,
        target=norm_target,
        status=EnforcementStatus.REQUESTED,
        provider="mock_local_provider",
        is_demo=True,
        requested_by_user_id=user.id,
        execution_details=exec_details,
    )
    db.add(action)
    db.flush()

    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.ENFORCEMENT_REQUESTED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={
            "enforcement_action_id": action.id,
            "action_type": action.action_type.value,
            "target": action.target,
            "status": action.status.value,
        },
    )
    db.commit()
    db.refresh(action)
    return action


def authorize_enforcement(
    db: Session,
    *,
    user: User,
    investigation_id: str,
    action_id: str,
) -> EnforcementAction:
    """Authorizes an enforcement action. Requires ANALYST or ADMIN role."""
    require_analyst_or_admin(user)
    inv = get_investigation(db, user=user, investigation_id=investigation_id)

    action = db.get(EnforcementAction, action_id)
    if not action or action.investigation_id != inv.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Enforcement action not found")

    if action.status != EnforcementStatus.REQUESTED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot authorize enforcement action in status {action.status.value}. Must be REQUESTED.",
        )

    action.status = EnforcementStatus.AUTHORIZED
    action.authorized_by_user_id = user.id
    action.updated_at = datetime.now(timezone.utc)
    db.flush()

    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.ENFORCEMENT_AUTHORIZED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={
            "enforcement_action_id": action.id,
            "action_type": action.action_type.value,
            "target": action.target,
            "status": action.status.value,
        },
    )
    db.commit()
    db.refresh(action)
    return action


def execute_enforcement(
    db: Session,
    *,
    user: User,
    investigation_id: str,
    action_id: str,
    provider: Optional[EnforcementProvider] = None,
    simulate_failure: bool = False,
) -> EnforcementAction:
    """
    Executes an authorized enforcement action through the provider abstraction.
    Requires ANALYST or ADMIN role.
    """
    require_analyst_or_admin(user)
    inv = get_investigation(db, user=user, investigation_id=investigation_id)

    action = db.get(EnforcementAction, action_id)
    if not action or action.investigation_id != inv.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Enforcement action not found")

    if action.status != EnforcementStatus.AUTHORIZED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot execute enforcement action in status {action.status.value}. Must be AUTHORIZED first.",
        )

    exec_provider = provider or get_default_enforcement_provider()
    context = {"simulate_failure": simulate_failure}

    # Execute through provider abstraction
    if action.action_type == EnforcementActionType.BLOCK_SENDER:
        result = exec_provider.block_sender(action.target, context)
    elif action.action_type == EnforcementActionType.BLOCK_DOMAIN:
        result = exec_provider.block_domain(action.target, context)
    elif action.action_type == EnforcementActionType.BLOCK_IP:
        result = exec_provider.block_ip(action.target, context)
    elif action.action_type == EnforcementActionType.QUARANTINE:
        result = exec_provider.quarantine(action.target, context)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported action type: {action.action_type}")

    action.executed_by_user_id = user.id
    action.provider = result.provider
    action.is_demo = result.is_demo
    action.execution_details = {
        "provider_message": result.message,
        "provider_details": result.details,
    }
    action.updated_at = datetime.now(timezone.utc)

    if result.status == "EXECUTED":
        action.status = EnforcementStatus.EXECUTED
        audit_action = AuditAction.ENFORCEMENT_EXECUTED
    else:
        action.status = EnforcementStatus.FAILED
        action.failure_reason = result.message
        audit_action = AuditAction.ENFORCEMENT_FAILED

    db.flush()
    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=audit_action,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={
            "enforcement_action_id": action.id,
            "action_type": action.action_type.value,
            "target": action.target,
            "status": action.status.value,
            "provider": action.provider,
            "is_demo": action.is_demo,
            "message": result.message,
        },
    )
    db.commit()
    db.refresh(action)
    return action


def reject_enforcement(
    db: Session,
    *,
    user: User,
    investigation_id: str,
    action_id: str,
    reason: str,
) -> EnforcementAction:
    """Rejects an enforcement action. Requires ANALYST or ADMIN role."""
    require_analyst_or_admin(user)
    inv = get_investigation(db, user=user, investigation_id=investigation_id)

    action = db.get(EnforcementAction, action_id)
    if not action or action.investigation_id != inv.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Enforcement action not found")

    if action.status not in (EnforcementStatus.REQUESTED, EnforcementStatus.AUTHORIZED):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot reject enforcement action in status {action.status.value}.",
        )

    action.status = EnforcementStatus.REJECTED
    action.rejection_reason = reason
    action.updated_at = datetime.now(timezone.utc)
    db.flush()

    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.ENFORCEMENT_REJECTED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={
            "enforcement_action_id": action.id,
            "action_type": action.action_type.value,
            "target": action.target,
            "status": action.status.value,
            "reason": reason,
        },
    )
    db.commit()
    db.refresh(action)
    return action


def list_enforcement_actions(
    db: Session,
    *,
    user: User,
    investigation_id: str,
) -> List[EnforcementAction]:
    """Lists all enforcement actions for an investigation."""
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    return (
        db.query(EnforcementAction)
        .filter(EnforcementAction.investigation_id == inv.id)
        .order_by(EnforcementAction.created_at.desc())
        .all()
    )
