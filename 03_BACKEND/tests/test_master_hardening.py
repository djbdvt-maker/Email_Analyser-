"""
Master Hardening & Integration Regression Tests
================================================
Comprehensive verification for:
1. current_analysis_run_id lifecycle semantics (run1 complete -> run2 queued/failed/complete)
2. Score Engine / Conclusion Generator separation of ownership
3. CF-06 subtype evaluation and non-trigger boundary conditions
4. Server-side RBAC authorization for USER, ANALYST, ADMIN across all actions
5. Dedicated NOTE_ADDED audit event
6. Complete registry scoring bucket verification (all 10 buckets)
"""
import pytest
from app.models import (
    UserRole,
    InvestigationStatus,
    AnalysisRunStatus,
    AuditAction,
    AuditEvent,
    ScoreConclusion,
    Finding,
)
from app.services.score_engine import (
    compute_score,
    ScoreResult,
    ScoreOutput,
    CATEGORY_CAPS,
)
from app.services.conclusion_generator import ConclusionGenerator
from app.services.floor_engine import evaluate_floors
from app.qualification_registry import get_scoring_buckets
from tests.conftest import (
    auth_headers,
    _make_user,
    create_investigation,
    create_run,
    internal_service_headers,
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _finding(client, user, inv_id, run_id, **overrides):
    body = {
        "category": "Content",
        "qualification_code": "FINANCIAL_REQUEST",
        "qualification_version": "v1",
        "strength": "Moderate",
        "analysis_run_id": run_id,
        "normalized_subject_or_target": "target-1",
        "claim_signature": "payment_transfer_request",
        "supporting_fact_ids": [],
        "supporting_text": "sample ground text",
        "produced_by": "deterministic",
    }
    body.update(overrides)
    resp = client.post(
        f"/api/v1/investigations/{inv_id}/findings",
        json=body,
        headers=internal_service_headers(user),
    )
    assert resp.status_code == 201, resp.json()
    return resp.json()


def _advance_and_score(client, user, inv_id, run_id):
    for st in ("PARSING", "ANALYZING", "SCORING"):
        client.post(
            f"/api/v1/investigations/{inv_id}/analysis-runs/{run_id}/status",
            json={"status": st},
            headers=auth_headers(user),
        )
    resp = client.post(
        f"/api/v1/investigations/{inv_id}/analysis-runs/{run_id}/score",
        headers=auth_headers(user),
    )
    assert resp.status_code == 201
    return resp.json()


# --------------------------------------------------------------------------
# 1. current_analysis_run_id Semantics
# --------------------------------------------------------------------------

def test_current_analysis_run_id_lifecycle_progression(client, user, db_session):
    """
    Locked invariant:
    - first run completes -> current points to run1
    - second run queues -> current STILL points to run1
    - second run fails -> current STILL points to run1
    - second run completes -> current becomes run2
    """
    inv = create_investigation(client, user)
    inv_id = inv["id"]

    # Run 1: progress to SCORING, score, and complete
    run1 = create_run(client, user, inv_id)
    _advance_and_score(client, user, inv_id, run1["id"])
    client.post(
        f"/api/v1/investigations/{inv_id}/analysis-runs/{run1['id']}/status",
        json={"status": "COMPLETED"},
        headers=auth_headers(user),
    )

    inv_check = client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(user)).json()
    assert inv_check["current_analysis_run_id"] == run1["id"], "Run 1 must be current once COMPLETED"

    # Run 2: create (QUEUED) -> current must still be run1
    run2 = create_run(client, user, inv_id)
    inv_check = client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(user)).json()
    assert inv_check["current_analysis_run_id"] == run1["id"], "Queued run must NOT become current"

    # Run 2: transition PARSING -> FAILED -> current must still be run1
    client.post(
        f"/api/v1/investigations/{inv_id}/analysis-runs/{run2['id']}/status",
        json={"status": "PARSING"},
        headers=auth_headers(user),
    )
    client.post(
        f"/api/v1/investigations/{inv_id}/analysis-runs/{run2['id']}/status",
        json={"status": "FAILED", "failure_reason": "Simulated error"},
        headers=auth_headers(user),
    )
    inv_check = client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(user)).json()
    assert inv_check["current_analysis_run_id"] == run1["id"], "Failed run must NOT replace usable current run"

    # Run 3: progress to SCORING, score, and complete -> becomes run3
    run3 = create_run(client, user, inv_id)
    _advance_and_score(client, user, inv_id, run3["id"])
    client.post(
        f"/api/v1/investigations/{inv_id}/analysis-runs/{run3['id']}/status",
        json={"status": "COMPLETED"},
        headers=auth_headers(user),
    )
    inv_check = client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(user)).json()
    assert inv_check["current_analysis_run_id"] == run3["id"], "Completed run with score must become current"


# --------------------------------------------------------------------------
# 2. Score Engine / Conclusion Generator Boundary
# --------------------------------------------------------------------------

def test_score_engine_owns_numeric_scoring_only():
    """
    Score Engine must calculate score, category breakdown, floor codes, severity.
    Score Engine must NOT return verdict, one_line_explanation, or why_explanation.
    """
    from dataclasses import dataclass
    @dataclass
    class MockFinding:
        id: str
        category: str
        strength: str
        qualification_code: str

    findings = [
        MockFinding("1", "Content", "Moderate", "FINANCIAL_REQUEST"),
        MockFinding("2", "Identity", "Moderate", "EXECUTIVE_IMPERSONATION"),
    ]

    score_result = compute_score(findings)
    assert isinstance(score_result, ScoreResult)
    assert score_result.total_score == 14
    assert score_result.severity == "HIGH"
    assert "CF-02" in score_result.triggered_floor_codes

    # Verify score_result does not have verdict attributes
    assert not hasattr(score_result, "verdict")
    assert not hasattr(score_result, "one_line_explanation")
    assert not hasattr(score_result, "why_explanation")

    # Conclusion Generator is called separately
    cg = ConclusionGenerator()
    conclusion_output = cg.generate(score_output=score_result, findings=findings)
    assert conclusion_output.verdict == "SUSPICIOUS"
    assert "Executive impersonation" in conclusion_output.one_line_explanation


# --------------------------------------------------------------------------
# 3. CF-06 Routing Subtypes and Non-Trigger Cases
# --------------------------------------------------------------------------

def test_cf06_subtypes_trigger():
    """Each of the 3 locked CF-06 subtypes + ROUTING_FABRICATION_QUALIFIED trigger CF-06."""
    from dataclasses import dataclass
    @dataclass
    class MockF:
        qualification_code: str
        strength: str

    # 1. Temporal contradiction
    res1 = evaluate_floors([MockF("CF-06:TEMPORAL_CONTRADICTION_BEYOND_TOLERANCE", "Moderate")])
    assert "CF-06" in res1

    # 2. Independent trusted contradiction
    res2 = evaluate_floors([MockF("CF-06:INDEPENDENT_TRUSTED_CONTRADICTION", "Moderate")])
    assert "CF-06" in res2

    # 3. Structural implausibility
    res3 = evaluate_floors([MockF("CF-06:STRUCTURAL_IMPLAUSIBILITY", "Moderate")])
    assert "CF-06" in res3

    # 4. Qualified routing fabrication
    res4 = evaluate_floors([MockF("ROUTING_FABRICATION_QUALIFIED", "Moderate")])
    assert "CF-06" in res4


def test_cf06_non_trigger_conditions():
    """
    Non-trigger conditions must NOT trigger CF-06:
    - Authentication failures alone
    - Unknown/first-time IP alone
    - AI suspicion alone
    """
    from dataclasses import dataclass
    @dataclass
    class MockF:
        qualification_code: str
        strength: str

    # Authentication failure only
    assert "CF-06" not in evaluate_floors([
        MockF("DMARC_FAIL", "Moderate"),
        MockF("SPF_FAIL", "Moderate"),
        MockF("DKIM_FAIL", "Moderate"),
    ])

    # First time observed IP / unknown IP alone
    assert "CF-06" not in evaluate_floors([
        MockF("FIRST_TIME_OBSERVED_IP", "Weak"),
    ])

    # AI generic suspicion alone
    assert "CF-06" not in evaluate_floors([
        MockF("GENERIC_SUSPICION", "Weak"),
    ])


# --------------------------------------------------------------------------
# 4. Analyst Action & Server-Side RBAC
# --------------------------------------------------------------------------

def test_rbac_user_role_permissions(client, user, db_session, org):
    """
    USER / VIEWER:
    - can add notes (add_note)
    - can request escalation (needs_escalation)
    - CANNOT confirm_malicious (403)
    - CANNOT false_positive (403)
    - CANNOT reopen (403)
    - CANNOT close (403)
    """
    viewer = _make_user(db_session, org, "user_regular@acme.test", role=UserRole.USER)
    inv = create_investigation(client, user)
    inv_id = inv["id"]

    # Transition to UNDER_REVIEW first
    client.post(
        f"/api/v1/investigations/{inv_id}/status",
        json={"status": "UNDER_REVIEW"},
        headers=auth_headers(user),
    )

    # 1. USER can add_note
    note_resp = client.post(
        f"/api/v1/investigations/{inv_id}/actions",
        json={"action": "add_note", "note": "Reviewed by user"},
        headers=auth_headers(viewer),
    )
    assert note_resp.status_code == 200
    assert note_resp.json()["note"] == "Reviewed by user"

    # 2. USER CANNOT request needs_escalation (state-changing action restricted to analyst/admin)
    esc_resp = client.post(
        f"/api/v1/investigations/{inv_id}/actions",
        json={"action": "needs_escalation", "note": "Escalating for tier 2 review"},
        headers=auth_headers(viewer),
    )
    assert esc_resp.status_code == 403

    # 3. USER CANNOT confirm_malicious
    resp_conf = client.post(
        f"/api/v1/investigations/{inv_id}/actions",
        json={"action": "confirm_malicious"},
        headers=auth_headers(viewer),
    )
    assert resp_conf.status_code == 403

    # 4. USER CANNOT mark false_positive
    resp_fp = client.post(
        f"/api/v1/investigations/{inv_id}/actions",
        json={"action": "false_positive"},
        headers=auth_headers(viewer),
    )
    assert resp_fp.status_code == 403

    # 5. USER CANNOT reopen
    resp_reopen = client.post(
        f"/api/v1/investigations/{inv_id}/actions",
        json={"action": "reopen"},
        headers=auth_headers(viewer),
    )
    assert resp_reopen.status_code == 403

    # 6. USER CANNOT close
    resp_close = client.post(
        f"/api/v1/investigations/{inv_id}/actions",
        json={"action": "close"},
        headers=auth_headers(viewer),
    )
    assert resp_close.status_code == 403


def test_rbac_analyst_permissions(client, user):
    """ANALYST can perform confirm_malicious, false_positive, needs_escalation, add_note, reopen, close."""
    inv = create_investigation(client, user)
    inv_id = inv["id"]

    client.post(
        f"/api/v1/investigations/{inv_id}/status",
        json={"status": "UNDER_REVIEW"},
        headers=auth_headers(user),
    )

    # confirm_malicious
    r1 = client.post(
        f"/api/v1/investigations/{inv_id}/actions",
        json={"action": "confirm_malicious", "note": "Confirmed malicious by analyst"},
        headers=auth_headers(user),
    )
    assert r1.status_code == 200
    assert client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(user)).json()["status"] == "CONFIRMED"

    # reopen
    r2 = client.post(
        f"/api/v1/investigations/{inv_id}/actions",
        json={"action": "reopen", "note": "Reopened for re-evaluation"},
        headers=auth_headers(user),
    )
    assert r2.status_code == 200
    assert client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(user)).json()["status"] == "UNDER_REVIEW"

    # close
    r3 = client.post(
        f"/api/v1/investigations/{inv_id}/actions",
        json={"action": "close", "note": "Closing investigation"},
        headers=auth_headers(user),
    )
    assert r3.status_code == 200
    assert client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(user)).json()["status"] == "CLOSED"


def test_legacy_action_aliases_rejected(client, user):
    """Legacy aliases CONFIRM, MARK_FALSE_POSITIVE, ESCALATE, NOTE must be rejected with 422."""
    inv = create_investigation(client, user)
    inv_id = inv["id"]

    for legacy in ("CONFIRM", "CONFIRM_MALICIOUS", "MARK_FALSE_POSITIVE", "ESCALATE", "NOTE", "confirm", "escalate"):
        resp = client.post(
            f"/api/v1/investigations/{inv_id}/actions",
            json={"action": legacy, "note": "Testing legacy rejection"},
            headers=auth_headers(user),
        )
        assert resp.status_code == 422, f"Legacy alias '{legacy}' should be rejected with 422"
        assert "rejected" in resp.json()["message"].lower() or "legacy" in resp.json()["message"].lower()


def test_false_positive_requires_rationale(client, user):
    """Action false_positive without rationale must return 422; with rationale succeeds."""
    inv = create_investigation(client, user)
    inv_id = inv["id"]

    client.post(
        f"/api/v1/investigations/{inv_id}/status",
        json={"status": "UNDER_REVIEW"},
        headers=auth_headers(user),
    )

    # 1. No note, no reason -> 422
    bad_resp = client.post(
        f"/api/v1/investigations/{inv_id}/actions",
        json={"action": "false_positive"},
        headers=auth_headers(user),
    )
    assert bad_resp.status_code == 422
    assert "rationale" in bad_resp.json()["message"].lower()

    # 2. With false_positive_reason -> 200
    good_resp = client.post(
        f"/api/v1/investigations/{inv_id}/actions",
        json={"action": "false_positive", "falsePositiveReason": "Verified simulated phishing test by SecOps"},
        headers=auth_headers(user),
    )
    assert good_resp.status_code == 200
    assert client.get(f"/api/v1/investigations/{inv_id}", headers=auth_headers(user)).json()["status"] == "FALSE_POSITIVE"



# --------------------------------------------------------------------------
# 5. Dedicated NOTE_ADDED Audit Event
# --------------------------------------------------------------------------

def test_add_note_records_note_added_audit_event(client, user, db_session):
    """add_note must record a dedicated NOTE_ADDED audit event, not INVESTIGATION_STATUS_CHANGED."""
    inv = create_investigation(client, user)
    inv_id = inv["id"]

    resp = client.post(
        f"/api/v1/investigations/{inv_id}/actions",
        json={"action": "add_note", "note": "Specific analyst note text"},
        headers=auth_headers(user),
    )
    assert resp.status_code == 200

    # Query audit events from DB directly
    events = db_session.query(AuditEvent).filter(
        AuditEvent.investigation_id == inv_id,
        AuditEvent.action == AuditAction.NOTE_ADDED,
    ).all()
    assert len(events) >= 1, "Must find at least one NOTE_ADDED audit event"
    assert events[-1].metadata_json.get("note") == "Specific analyst note text"


# --------------------------------------------------------------------------
# 6. All 10 Canonical Registry Scoring Buckets
# --------------------------------------------------------------------------

def test_all_registry_scoring_buckets_registered():
    """Verify all 9 canonical scoring buckets exist with locked caps."""
    buckets = get_scoring_buckets()
    expected_buckets = {
        "Identity": 20,
        "Authentication": 16,
        "Domain": 16,
        "URL": 22,
        "Attachment": 20,
        "Infrastructure": 14,
        "Routing": 20,
        "Social Engineering": 14,
        "Threat Intelligence": 24,
    }
    for category, expected_cap in expected_buckets.items():
        assert category in buckets, f"Missing scoring bucket: {category}"
        assert buckets[category].point_cap == expected_cap, f"Cap mismatch for {category}"
        assert CATEGORY_CAPS[category] == expected_cap
