"""
Tests for Bot-Initiated Actions as Drafts (HZ4).
================================================
Verifies:
1. Invariant 7: Never an automatic irreversible action.
   Bot proposes action -> ActionDraft in PENDING_CONFIRMATION.
   Underlying irreversible action does NOT execute automatically.
2. Grounding verification: proposed enforcement actions must target grounded entities.
3. RBAC: regular USER / VIEWER cannot confirm sensitive actions (403).
4. Human confirmation: ANALYST or ADMIN confirms draft -> triggers execution, transitions to CONFIRMED.
5. Audit trail: logs actor_via="botchain" and confirmed_by=<user_id>.
6. Human rejection: ANALYST rejects draft with reason -> transitions to REJECTED.
7. Conflict: cannot re-confirm or re-reject a finalized draft (409).
8. Tool-facing API: POST /api/v1/tool/investigations/{id}/propose-action and manifest integration.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    ActionDraft,
    ActionDraftStatus,
    AuditEvent,
    AuditAction,
    EnforcementAction,
    EnforcementStatus,
    Fact,
    Investigation,
    UserRole,
)
from tests.conftest import auth_headers, _make_user


def _setup_inv_with_grounding(client, db_session, org, analyst):
    headers = auth_headers(analyst)
    inv_res = client.post("/api/v1/investigations", json={"title": "Action Draft Test"}, headers=headers)
    assert inv_res.status_code == 201
    inv_id = inv_res.json()["id"]

    # Grounded sender and domain
    f1 = Fact(
        investigation_id=inv_id,
        analysis_run_id="run-placeholder",
        fact_type="envelope_metadata",
        payload={
            "from_address": "malicious@phishing-lure.com",
            "from_domain": "phishing-lure.com",
        },
        produced_by="deterministic",
    )
    db_session.add(f1)

    inv = db_session.get(Investigation, inv_id)
    inv.current_analysis_run_id = "run-placeholder"
    db_session.commit()
    return inv_id


def test_bot_creates_draft_status_pending_confirmation(client: TestClient, db_session: Session, org):
    """
    Bot proposes an action -> draft is created in PENDING_CONFIRMATION.
    Invariant 7: No irreversible action is executed automatically.
    """
    analyst = _make_user(db_session, org, "analyst_bot@test.org", role=UserRole.ANALYST)
    inv_id = _setup_inv_with_grounding(client, db_session, org, analyst)
    headers = auth_headers(analyst)

    payload = {
        "action_type": "BLOCK_SENDER",
        "proposed_payload": {
            "target": "malicious@phishing-lure.com",
            "reason": "Suspicious credential harvester detected by bot",
        },
        "created_by_actor": "botchain",
    }
    res = client.post(f"/api/v1/investigations/{inv_id}/actions/draft", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()

    assert data["status"] == "PENDING_CONFIRMATION"
    assert data["action_type"] == "BLOCK_SENDER"
    assert data["created_by_bot"] is True
    assert data["created_by_actor"] == "botchain"
    assert data["confirmed_by_user_id"] is None
    assert data["confirmed_at"] is None

    # INVARIANT 7 PROOF: Verify NO enforcement action was executed or requested in enforcement_actions table
    enf_actions = db_session.query(EnforcementAction).filter(EnforcementAction.investigation_id == inv_id).all()
    assert len(enf_actions) == 0

    # Audit event ACTION_DRAFT_CREATED exists
    audit = db_session.query(AuditEvent).filter(
        AuditEvent.investigation_id == inv_id,
        AuditEvent.action == AuditAction.ACTION_DRAFT_CREATED,
    ).first()
    assert audit is not None
    assert audit.metadata_json["actor_via"] == "botchain"
    assert audit.metadata_json["draft_id"] == data["id"]


def test_list_and_get_drafts(client: TestClient, db_session: Session, org):
    """Verifies listing and retrieval of action drafts."""
    analyst = _make_user(db_session, org, "analyst_list@test.org", role=UserRole.ANALYST)
    inv_id = _setup_inv_with_grounding(client, db_session, org, analyst)
    headers = auth_headers(analyst)

    # Create two drafts
    d1 = client.post(
        f"/api/v1/investigations/{inv_id}/actions/draft",
        json={"action_type": "ADD_NOTE", "proposed_payload": {"note": "Bot observation 1"}},
        headers=headers,
    ).json()

    d2 = client.post(
        f"/api/v1/investigations/{inv_id}/actions/draft",
        json={"action_type": "BLOCK_DOMAIN", "proposed_payload": {"target": "phishing-lure.com"}},
        headers=headers,
    ).json()

    list_res = client.get(f"/api/v1/investigations/{inv_id}/actions/drafts", headers=headers)
    assert list_res.status_code == 200
    drafts = list_res.json()
    assert len(drafts) >= 2
    draft_ids = [d["id"] for d in drafts]
    assert d1["id"] in draft_ids
    assert d2["id"] in draft_ids

    # Single get
    get_res = client.get(f"/api/v1/investigations/{inv_id}/actions/drafts/{d1['id']}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["action_type"] == "ADD_NOTE"


def test_propose_enforcement_grounding_rejection(client: TestClient, db_session: Session, org):
    """Proposing an ungrounded enforcement target is rejected (400)."""
    analyst = _make_user(db_session, org, "analyst_ground@test.org", role=UserRole.ANALYST)
    inv_id = _setup_inv_with_grounding(client, db_session, org, analyst)
    headers = auth_headers(analyst)

    payload = {
        "action_type": "BLOCK_SENDER",
        "proposed_payload": {"target": "innocent-target@random.com"},
    }
    res = client.post(f"/api/v1/investigations/{inv_id}/actions/draft", json=payload, headers=headers)
    assert res.status_code == 400
    assert "not grounded in this investigation's evidence" in res.json()["message"]


def test_non_analyst_cannot_confirm_sensitive_draft(client: TestClient, db_session: Session, org):
    """Regular USER/VIEWER role cannot confirm sensitive actions (403)."""
    analyst = _make_user(db_session, org, "analyst_rbac@test.org", role=UserRole.ANALYST)
    viewer = _make_user(db_session, org, "viewer_rbac@test.org", role=UserRole.VIEWER)
    inv_id = _setup_inv_with_grounding(client, db_session, org, analyst)

    # Propose BLOCK_SENDER
    d = client.post(
        f"/api/v1/investigations/{inv_id}/actions/draft",
        json={"action_type": "BLOCK_SENDER", "proposed_payload": {"target": "malicious@phishing-lure.com"}},
        headers=auth_headers(analyst),
    ).json()

    # Viewer tries to confirm
    res = client.post(
        f"/api/v1/investigations/{inv_id}/actions/drafts/{d['id']}/confirm",
        json={},
        headers=auth_headers(viewer),
    )
    assert res.status_code == 403
    assert "requires ANALYST or ADMIN" in res.json()["message"]


def test_analyst_confirms_enforcement_draft(client: TestClient, db_session: Session, org):
    """
    Analyst confirms an enforcement draft:
    1. Status transitions to CONFIRMED.
    2. Underlying enforcement action is created.
    3. confirmed_by_user_id and confirmed_at are populated.
    4. Audit event ACTION_DRAFT_CONFIRMED records actor_via and confirmed_by.
    """
    analyst = _make_user(db_session, org, "analyst_exec@test.org", role=UserRole.ANALYST)
    inv_id = _setup_inv_with_grounding(client, db_session, org, analyst)
    headers = auth_headers(analyst)

    # Propose
    d = client.post(
        f"/api/v1/investigations/{inv_id}/actions/draft",
        json={
            "action_type": "BLOCK_SENDER",
            "proposed_payload": {"target": "malicious@phishing-lure.com"},
            "created_by_actor": "botchain",
        },
        headers=headers,
    ).json()

    # Confirm
    confirm_res = client.post(
        f"/api/v1/investigations/{inv_id}/actions/drafts/{d['id']}/confirm",
        json={"execution_notes": "Analyst reviewed forensic indicators and approved block"},
        headers=headers,
    )
    assert confirm_res.status_code == 200
    confirmed_data = confirm_res.json()

    assert confirmed_data["status"] == "CONFIRMED"
    assert confirmed_data["confirmed_by_user_id"] == analyst.id
    assert confirmed_data["confirmed_at"] is not None
    assert confirmed_data["execution_result"] is not None
    assert "enforcement_action_id" in confirmed_data["execution_result"]

    # Verify enforcement action exists in DB
    enf_id = confirmed_data["execution_result"]["enforcement_action_id"]
    enf = db_session.get(EnforcementAction, enf_id)
    assert enf is not None
    assert enf.target == "malicious@phishing-lure.com"
    assert enf.status == EnforcementStatus.REQUESTED

    # Verify audit event
    audit = db_session.query(AuditEvent).filter(
        AuditEvent.investigation_id == inv_id,
        AuditEvent.action == AuditAction.ACTION_DRAFT_CONFIRMED,
    ).first()
    assert audit is not None
    assert audit.metadata_json["actor_via"] == "botchain"
    assert audit.metadata_json["confirmed_by"] == analyst.id


def test_analyst_rejects_draft(client: TestClient, db_session: Session, org):
    """Analyst rejects a draft with a mandatory reason."""
    analyst = _make_user(db_session, org, "analyst_rej@test.org", role=UserRole.ANALYST)
    inv_id = _setup_inv_with_grounding(client, db_session, org, analyst)
    headers = auth_headers(analyst)

    d = client.post(
        f"/api/v1/investigations/{inv_id}/actions/draft",
        json={"action_type": "ADD_NOTE", "proposed_payload": {"note": "Unnecessary bot note"}},
        headers=headers,
    ).json()

    reject_res = client.post(
        f"/api/v1/investigations/{inv_id}/actions/drafts/{d['id']}/reject",
        json={"reason": "Redundant information, note already exists on case"},
        headers=headers,
    )
    assert reject_res.status_code == 200
    rejected_data = reject_res.json()

    assert rejected_data["status"] == "REJECTED"
    assert rejected_data["rejection_reason"] == "Redundant information, note already exists on case"

    # Verify conflict on re-confirming rejected draft
    reconfirm_res = client.post(
        f"/api/v1/investigations/{inv_id}/actions/drafts/{d['id']}/confirm",
        json={},
        headers=headers,
    )
    assert reconfirm_res.status_code == 409


def test_tool_api_propose_action(client: TestClient, db_session: Session, org):
    """Tests the BotChain tool-facing endpoint and manifest registration."""
    analyst = _make_user(db_session, org, "analyst_tool@test.org", role=UserRole.ANALYST)
    inv_id = _setup_inv_with_grounding(client, db_session, org, analyst)
    headers = auth_headers(analyst)

    # 1. Check manifest includes propose_action
    manifest_res = client.get("/tool-manifest")
    assert manifest_res.status_code == 200
    op_names = [op["name"] for op in manifest_res.json()["operations"]]
    assert "propose_action" in op_names

    # 2. Call tool endpoint
    tool_res = client.post(
        f"/api/v1/tool/investigations/{inv_id}/propose-action",
        json={
            "action_type": "ADD_NOTE",
            "proposed_payload": {"note": "BotChain automated investigation summary attached"},
            "created_by_actor": "botchain-orchestrator",
        },
        headers=headers,
    )
    assert tool_res.status_code == 201
    draft_data = tool_res.json()
    assert draft_data["status"] == "PENDING_CONFIRMATION"
    assert draft_data["created_by_actor"] == "botchain-orchestrator"
    assert draft_data["created_by_bot"] is True
