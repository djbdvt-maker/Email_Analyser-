"""
API Router for Threat Response & Enforcement Actions.
====================================================
Provides endpoints for:
- GET /api/v1/investigations/{id}/enforcement/options
- GET /api/v1/investigations/{id}/enforcement
- POST /api/v1/investigations/{id}/enforcement/request
- POST /api/v1/investigations/{id}/enforcement/{action_id}/authorize
- POST /api/v1/investigations/{id}/enforcement/{action_id}/execute
- POST /api/v1/investigations/{id}/enforcement/{action_id}/reject
"""
from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import (
    EnforcementActionOut,
    EnforcementRequestCreate,
    EnforcementRejectionCreate,
    EnforcementExecuteCreate,
    GroundedOptionOut,
)
from app.security import get_current_user
from app.services import enforcement_service

router = APIRouter(prefix="/api/v1/investigations/{investigation_id}/enforcement", tags=["threat-enforcement"])


@router.get("/options", response_model=List[GroundedOptionOut])
def get_enforcement_options(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Returns available enforcement action options grounded in this investigation's
    forensic evidence (observed senders, domains, and IP addresses).
    """
    return enforcement_service.get_available_enforcement_options(
        db, user=user, investigation_id=investigation_id
    )


@router.get("", response_model=List[EnforcementActionOut])
def list_enforcement_actions(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Lists all enforcement actions recorded for this investigation."""
    return enforcement_service.list_enforcement_actions(
        db, user=user, investigation_id=investigation_id
    )


@router.post("/request", response_model=EnforcementActionOut, status_code=201)
def request_enforcement(
    investigation_id: str,
    body: EnforcementRequestCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Requests a new enforcement action (BLOCK_SENDER, BLOCK_DOMAIN, BLOCK_IP, QUARANTINE).
    Normalizes the target and validates grounding against investigation evidence.
    Initial state: REQUESTED.
    """
    return enforcement_service.request_enforcement(
        db,
        user=user,
        investigation_id=investigation_id,
        action_type=body.action_type,
        target=body.target,
        context=body.context,
    )


@router.post("/{action_id}/authorize", response_model=EnforcementActionOut)
def authorize_enforcement(
    investigation_id: str,
    action_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Authorizes an enforcement action. Requires ANALYST or ADMIN role.
    Transitions state from REQUESTED to AUTHORIZED.
    """
    return enforcement_service.authorize_enforcement(
        db,
        user=user,
        investigation_id=investigation_id,
        action_id=action_id,
    )


@router.post("/{action_id}/execute", response_model=EnforcementActionOut)
def execute_enforcement(
    investigation_id: str,
    action_id: str,
    body: EnforcementExecuteCreate = EnforcementExecuteCreate(),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Executes an authorized enforcement action through the provider-neutral abstraction.
    Requires ANALYST or ADMIN role.
    Transitions state from AUTHORIZED to EXECUTED (or FAILED).
    """
    return enforcement_service.execute_enforcement(
        db,
        user=user,
        investigation_id=investigation_id,
        action_id=action_id,
        simulate_failure=body.simulate_failure or False,
    )


@router.post("/{action_id}/reject", response_model=EnforcementActionOut)
def reject_enforcement(
    investigation_id: str,
    action_id: str,
    body: EnforcementRejectionCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Rejects an enforcement action. Requires ANALYST or ADMIN role.
    Transitions state to REJECTED with mandatory reason.
    """
    return enforcement_service.reject_enforcement(
        db,
        user=user,
        investigation_id=investigation_id,
        action_id=action_id,
        reason=body.reason,
    )
