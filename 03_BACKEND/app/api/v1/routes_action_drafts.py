"""
API Router for Bot & User Action Drafts.
========================================
Endpoints:
- POST /api/v1/investigations/{investigation_id}/actions/draft
- GET  /api/v1/investigations/{investigation_id}/actions/drafts
- GET  /api/v1/investigations/{investigation_id}/actions/drafts/{draft_id}
- POST /api/v1/investigations/{investigation_id}/actions/drafts/{draft_id}/confirm
- POST /api/v1/investigations/{investigation_id}/actions/drafts/{draft_id}/reject
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import (
    ActionDraftCreate,
    ActionDraftConfirm,
    ActionDraftReject,
    ActionDraftOut,
)
from app.security import get_current_user
from app.services import action_draft_service

router = APIRouter(
    prefix="/api/v1/investigations/{investigation_id}/actions",
    tags=["action-drafts"],
)


@router.post(
    "/draft",
    response_model=ActionDraftOut,
    status_code=status.HTTP_201_CREATED,
    summary="Propose an action draft",
    description="Proposes an action (e.g. BLOCK_SENDER, QUARANTINE, ADD_NOTE). The action is saved as a draft in PENDING_CONFIRMATION status and NEVER executes automatically.",
)
def propose_action_draft(
    investigation_id: str,
    body: ActionDraftCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return action_draft_service.create_action_draft(
        db,
        user=user,
        investigation_id=investigation_id,
        action_type=body.action_type,
        proposed_payload=body.proposed_payload,
        created_by_actor=body.created_by_actor or "botchain",
    )


@router.get(
    "/drafts",
    response_model=List[ActionDraftOut],
    summary="List action drafts",
    description="Lists all action drafts for this investigation.",
)
def list_action_drafts(
    investigation_id: str,
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (PENDING_CONFIRMATION, CONFIRMED, REJECTED)"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return action_draft_service.list_action_drafts(
        db,
        user=user,
        investigation_id=investigation_id,
        status_filter=status_filter,
    )


@router.get(
    "/drafts/{draft_id}",
    response_model=ActionDraftOut,
    summary="Get action draft",
    description="Retrieves a single action draft by ID.",
)
def get_action_draft(
    investigation_id: str,
    draft_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return action_draft_service.get_action_draft(
        db,
        user=user,
        investigation_id=investigation_id,
        draft_id=draft_id,
    )


@router.post(
    "/drafts/{draft_id}/confirm",
    response_model=ActionDraftOut,
    summary="Confirm an action draft",
    description="Confirms and triggers the execution of an action draft. Requires ANALYST or ADMIN role for sensitive actions.",
)
def confirm_action_draft(
    investigation_id: str,
    draft_id: str,
    body: ActionDraftConfirm = ActionDraftConfirm(),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return action_draft_service.confirm_action_draft(
        db,
        user=user,
        investigation_id=investigation_id,
        draft_id=draft_id,
        execution_notes=body.execution_notes,
    )


@router.post(
    "/drafts/{draft_id}/reject",
    response_model=ActionDraftOut,
    summary="Reject an action draft",
    description="Rejects an action draft with a mandatory justification reason. Requires ANALYST or ADMIN role.",
)
def reject_action_draft(
    investigation_id: str,
    draft_id: str,
    body: ActionDraftReject,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return action_draft_service.reject_action_draft(
        db,
        user=user,
        investigation_id=investigation_id,
        draft_id=draft_id,
        reason=body.reason,
    )
