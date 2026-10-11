"""
Action Draft Service for Bot & User-Initiated Proposed Actions.
==============================================================
Enforces Invariant 7 ("Never an automatic irreversible action") and Invariant 8:
1. Proposed actions from bots (e.g. BotChain agents) or automated systems are
   persisted as ActionDraft entities in PENDING_CONFIRMATION status.
2. Irreversible actions (threat enforcement, blocking, quarantine, case closure)
   NEVER execute automatically.
3. Human operators (ANALYST or ADMIN) must explicitly review and confirm or reject
   the draft.
4. Audit events preserve provenance with `actor_via` (e.g. "botchain") and `confirmed_by`.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.models import (
    ActionDraft,
    ActionDraftStatus,
    AuditAction,
    User,
    UserRole,
)
from app.services import enforcement_service
from app.services import investigation_service
from app.services.investigation_service import get_investigation


def create_action_draft(
    db: Session,
    *,
    user: User,
    investigation_id: str,
    action_type: str,
    proposed_payload: Optional[Dict[str, Any]] = None,
    created_by_actor: str = "botchain",
) -> ActionDraft:
    """
    Creates an ActionDraft for human review.
    Initial status is always PENDING_CONFIRMATION.
    """
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    raw_type = (action_type or "").strip().upper()
    if not raw_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="action_type cannot be empty",
        )

    payload = proposed_payload or {}

    # If proposing an enforcement action, validate target grounding early
    if raw_type in ("BLOCK_SENDER", "BLOCK_DOMAIN", "BLOCK_IP", "QUARANTINE"):
        target = payload.get("target")
        if not target:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Proposed enforcement action '{raw_type}' requires 'target' in proposed_payload",
            )
        # Validate target syntax and grounding in current analysis run
        norm_target = enforcement_service.normalize_target(raw_type, target)
        enforcement_service.validate_target_grounded(db, inv, raw_type, norm_target)
        payload["target"] = norm_target

    draft = ActionDraft(
        organization_id=user.organization_id,
        investigation_id=inv.id,
        action_type=raw_type,
        proposed_payload=payload,
        status=ActionDraftStatus.PENDING_CONFIRMATION,
        created_by_bot=True if created_by_actor.lower() != "user" else False,
        created_by_actor=created_by_actor,
        created_by_user_id=user.id,
    )
    db.add(draft)
    db.flush()

    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.ACTION_DRAFT_CREATED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={
            "draft_id": draft.id,
            "action_type": draft.action_type,
            "actor_via": draft.created_by_actor,
            "proposed_payload": payload,
            "status": draft.status.value,
        },
    )
    db.commit()
    db.refresh(draft)
    return draft


def list_action_drafts(
    db: Session,
    *,
    user: User,
    investigation_id: str,
    status_filter: Optional[str] = None,
) -> List[ActionDraft]:
    """Lists all action drafts recorded for an investigation."""
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    query = db.query(ActionDraft).filter(ActionDraft.investigation_id == inv.id)
    if status_filter:
        try:
            enum_status = ActionDraftStatus(status_filter.upper())
            query = query.filter(ActionDraft.status == enum_status)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status filter: '{status_filter}'",
            )
    return query.order_by(ActionDraft.created_at.desc()).all()


def get_action_draft(
    db: Session,
    *,
    user: User,
    investigation_id: str,
    draft_id: str,
) -> ActionDraft:
    """Retrieves a specific action draft."""
    inv = get_investigation(db, user=user, investigation_id=investigation_id)
    draft = db.get(ActionDraft, draft_id)
    if not draft or draft.investigation_id != inv.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action draft '{draft_id}' not found for investigation '{investigation_id}'",
        )
    return draft


def confirm_action_draft(
    db: Session,
    *,
    user: User,
    investigation_id: str,
    draft_id: str,
    execution_notes: Optional[str] = None,
) -> ActionDraft:
    """
    Confirms and executes a pending action draft.
    Requires appropriate human permissions (ANALYST or ADMIN for enforcement/closure).
    """
    draft = get_action_draft(db, user=user, investigation_id=investigation_id, draft_id=draft_id)
    inv = get_investigation(db, user=user, investigation_id=investigation_id)

    if draft.status != ActionDraftStatus.PENDING_CONFIRMATION:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot confirm draft in status '{draft.status.value}'. Must be PENDING_CONFIRMATION.",
        )

    # RBAC check: State-changing, enforcement, or case resolution actions require ANALYST or ADMIN
    sensitive_actions = {
        "BLOCK_SENDER",
        "BLOCK_DOMAIN",
        "BLOCK_IP",
        "QUARANTINE",
        "CONFIRM_MALICIOUS",
        "FALSE_POSITIVE",
        "NEEDS_ESCALATION",
        "CLOSE",
        "REOPEN",
    }
    if draft.action_type in sensitive_actions and user.role not in (UserRole.ANALYST, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Confirming action '{draft.action_type}' requires ANALYST or ADMIN role.",
        )

    execution_result: Dict[str, Any] = {}

    # Execute underlying action based on type
    if draft.action_type in ("BLOCK_SENDER", "BLOCK_DOMAIN", "BLOCK_IP", "QUARANTINE"):
        target = draft.proposed_payload.get("target")
        enforcement_act = enforcement_service.request_enforcement(
            db,
            user=user,
            investigation_id=inv.id,
            action_type=draft.action_type,
            target=target,
            context={
                "confirmed_from_draft": draft.id,
                "created_by_actor": draft.created_by_actor,
                "notes": execution_notes,
            },
        )
        execution_result = {
            "enforcement_action_id": enforcement_act.id,
            "status": enforcement_act.status.value,
            "target": enforcement_act.target,
            "action_type": enforcement_act.action_type.value,
        }
    elif draft.action_type == "ADD_NOTE":
        note_text = draft.proposed_payload.get("note") or execution_notes or "Note confirmed from bot draft"
        res = investigation_service.record_analyst_action(
            db,
            user=user,
            investigation_id=inv.id,
            action="add_note",
            note=note_text,
        )
        execution_result = res
    elif draft.action_type.lower() in investigation_service.CANONICAL_ANALYST_ACTIONS:
        res = investigation_service.record_analyst_action(
            db,
            user=user,
            investigation_id=inv.id,
            action=draft.action_type.lower(),
            note=execution_notes or draft.proposed_payload.get("note"),
            false_positive_reason=draft.proposed_payload.get("false_positive_reason"),
        )
        execution_result = res
    else:
        execution_result = {
            "status": "EXECUTED",
            "notes": execution_notes,
            "custom_payload": draft.proposed_payload,
        }

    now = datetime.now(timezone.utc)
    draft.status = ActionDraftStatus.CONFIRMED
    draft.confirmed_by_user_id = user.id
    draft.confirmed_at = now
    draft.execution_result = execution_result
    draft.updated_at = now

    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.ACTION_DRAFT_CONFIRMED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={
            "draft_id": draft.id,
            "action_type": draft.action_type,
            "actor_via": draft.created_by_actor,
            "confirmed_by": user.id,
            "confirmed_by_email": user.email,
            "execution_result": execution_result,
        },
    )
    db.commit()
    db.refresh(draft)
    return draft


def reject_action_draft(
    db: Session,
    *,
    user: User,
    investigation_id: str,
    draft_id: str,
    reason: str,
) -> ActionDraft:
    """
    Rejects a pending action draft.
    Requires ANALYST or ADMIN role.
    """
    if user.role not in (UserRole.ANALYST, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Rejecting action drafts requires ANALYST or ADMIN role.",
        )

    draft = get_action_draft(db, user=user, investigation_id=investigation_id, draft_id=draft_id)
    inv = get_investigation(db, user=user, investigation_id=investigation_id)

    if draft.status != ActionDraftStatus.PENDING_CONFIRMATION:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot reject draft in status '{draft.status.value}'. Must be PENDING_CONFIRMATION.",
        )

    now = datetime.now(timezone.utc)
    draft.status = ActionDraftStatus.REJECTED
    draft.rejection_reason = reason
    draft.confirmed_by_user_id = user.id
    draft.confirmed_at = now
    draft.updated_at = now

    record_audit_event(
        db,
        organization_id=user.organization_id,
        action=AuditAction.ACTION_DRAFT_REJECTED,
        investigation_id=inv.id,
        actor_user_id=user.id,
        metadata={
            "draft_id": draft.id,
            "action_type": draft.action_type,
            "actor_via": draft.created_by_actor,
            "rejected_by": user.id,
            "reason": reason,
        },
    )
    db.commit()
    db.refresh(draft)
    return draft
