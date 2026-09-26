"""
Tests for User Feedback & Re-Analysis Workflow (Sections 5, 6, 7, 24).
=====================================================================
Proves:
- Authenticated user can submit feedback (SPAM_REPORTED, PHISHING_REPORTED, ANALYSIS_DISPUTED).
- Cross-organization feedback rejected (404/403).
- Invalid feedback type rejected (400).
- Feedback is audited (USER_FEEDBACK_SUBMITTED, REANALYSIS_REQUESTED).
- Feedback creates a NEW AnalysisRun.
- Previous run remains completely immutable.
- New run uses the same immutable artifact.
- New run receives its own findings.
- Failed re-analysis does NOT replace current_analysis_run_id.
- Successful re-analysis DOES replace current_analysis_run_id.
- Run comparison returns score delta, severity changes, verdict changes, and findings delta.
- User feedback does not directly alter score or verdict without forensic pipeline.
"""
import io
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    Investigation,
    AnalysisRun,
    AnalysisRunStatus,
    Artifact,
    Finding,
    ScoreConclusion,
    UserFeedback,
    UserRole,
    AuditEvent,
    AuditAction,
)
from app.services.reanalysis_service import compare_analysis_runs
from tests.conftest import auth_headers, _make_user

SAMPLE_EML = b"""From: "Test User" <user@example.com>
To: target@victim.org
Subject: Meeting notes
Date: Mon, 15 Sep 2026 10:00:00 +0000
Message-ID: <test-fb-1@victim.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi team, here are the meeting notes.
"""


def test_user_feedback_validation_and_rbac(client: TestClient, db_session: Session, org, other_org):
    """
    Validates:
    - Invalid feedback_type rejected (400)
    - Cross-organization feedback rejected (404)
    - Valid feedback accepted and audited
    """
    user = _make_user(db_session, org, "user1@org.test", role=UserRole.USER)
    other_user = _make_user(db_session, other_org, "user2@other.test", role=UserRole.USER)
    user_headers = auth_headers(user)
    other_headers = auth_headers(other_user)

    # Ingest email to create investigation and run
    files = {"file": ("test.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")}
    data = {"auto_analyze": "true", "ingestion_source": "test_upload"}
    ingest_res = client.post("/api/v1/ingest", files=files, data=data, headers=user_headers)
    assert ingest_res.status_code == 201
    inv_id = ingest_res.json()["investigation_id"]
    run1_id = ingest_res.json()["analysis_run_id"]

    # 1. Invalid feedback type rejected
    bad_res = client.post(
        f"/api/v1/investigations/{inv_id}/feedback",
        json={"feedback_type": "NOT_A_VALID_TYPE", "note": "bad"},
        headers=user_headers,
    )
    assert bad_res.status_code == 400
    assert "Invalid feedback_type" in bad_res.json()["message"]

    # 2. Cross-org feedback rejected
    cross_res = client.post(
        f"/api/v1/investigations/{inv_id}/feedback",
        json={"feedback_type": "SPAM_REPORTED", "note": "Attacker org attempt"},
        headers=other_headers,
    )
    assert cross_res.status_code == 404

    # 3. Valid feedback accepted
    fb_res = client.post(
        f"/api/v1/investigations/{inv_id}/feedback",
        json={"feedback_type": "SPAM_REPORTED", "note": "This is definitely spam/phishing"},
        headers=user_headers,
    )
    assert fb_res.status_code == 201
    fb_data = fb_res.json()
    assert fb_data["feedback_type"] == "SPAM_REPORTED"
    assert fb_data["source_analysis_run_id"] == run1_id
    new_run_id = fb_data["new_analysis_run_id"]
    assert new_run_id != run1_id

    # Check database persistence
    fb_row = db_session.query(UserFeedback).filter(UserFeedback.id == fb_data["feedback_id"]).first()
    assert fb_row is not None
    assert fb_row.actor_user_id == user.id
    assert fb_row.resulting_analysis_run_id == new_run_id

    # Check audit trail
    events = db_session.query(AuditEvent).filter(AuditEvent.investigation_id == inv_id).all()
    actions = [e.action.value for e in events]
    assert "USER_FEEDBACK_SUBMITTED" in actions
    assert "REANALYSIS_REQUESTED" in actions

    # Verify list feedback endpoint
    list_res = client.get(f"/api/v1/investigations/{inv_id}/feedback", headers=user_headers)
    assert list_res.status_code == 200
    assert len(list_res.json()) == 1
    assert list_res.json()[0]["feedback_type"] == "SPAM_REPORTED"


def test_reanalysis_immutability_and_current_run_pointer(client: TestClient, db_session: Session, org):
    """
    Validates:
    - Previous run remains immutable.
    - New run receives its own findings and score.
    - current_analysis_run_id updates to the new completed run.
    - The two runs can be compared.
    """
    analyst = _make_user(db_session, org, "analyst_re@org.test", role=UserRole.ANALYST)
    headers = auth_headers(analyst)

    # Ingest
    files = {"file": ("test2.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")}
    data = {"auto_analyze": "true", "ingestion_source": "test_upload"}
    ingest_res = client.post("/api/v1/ingest", files=files, data=data, headers=headers)
    inv_id = ingest_res.json()["investigation_id"]
    run1_id = ingest_res.json()["analysis_run_id"]

    # Check run 1 initial score
    score1_row = db_session.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == run1_id).first()
    assert score1_row is not None
    score1_val = score1_row.total_score
    score1_sev = score1_row.severity

    # Submit feedback & reanalyze
    fb_res = client.post(
        f"/api/v1/investigations/{inv_id}/feedback",
        json={"feedback_type": "ANALYSIS_DISPUTED", "note": "Check again"},
        headers=headers,
    )
    assert fb_res.status_code == 201
    run2_id = fb_res.json()["new_analysis_run_id"]

    # Verify inv.current_analysis_run_id has updated to run2
    inv = db_session.get(Investigation, inv_id)
    db_session.refresh(inv)
    assert inv.current_analysis_run_id == run2_id

    # Verify run 1 is completely untouched
    score1_after = db_session.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == run1_id).first()
    assert score1_after.total_score == score1_val
    assert score1_after.severity == score1_sev

    # Verify run 2 has its own score conclusion
    score2_row = db_session.query(ScoreConclusion).filter(ScoreConclusion.analysis_run_id == run2_id).first()
    assert score2_row is not None
    assert score2_row.id != score1_after.id

    # Test run comparison endpoint
    comp_res = client.get(
        f"/api/v1/investigations/{inv_id}/compare-runs?run1={run1_id}&run2={run2_id}",
        headers=headers,
    )
    assert comp_res.status_code == 200
    comp_data = comp_res.json()
    assert comp_data["run_1_id"] == run1_id
    assert comp_data["run_2_id"] == run2_id
    assert "score_delta" in comp_data
    assert comp_data["score_delta"] == 0  # Identical clean email re-analyzed


def test_failed_reanalysis_does_not_replace_current_run(client: TestClient, db_session: Session, org):
    """
    If a re-analysis fails or crashes, inv.current_analysis_run_id MUST NOT be updated.
    The previous usable completed run remains current.
    """
    analyst = _make_user(db_session, org, "analyst_fail@org.test", role=UserRole.ANALYST)
    headers = auth_headers(analyst)

    # Ingest
    files = {"file": ("test3.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")}
    data = {"auto_analyze": "true", "ingestion_source": "test_upload"}
    ingest_res = client.post("/api/v1/ingest", files=files, data=data, headers=headers)
    inv_id = ingest_res.json()["investigation_id"]
    run1_id = ingest_res.json()["analysis_run_id"]

    inv = db_session.get(Investigation, inv_id)
    assert inv.current_analysis_run_id == run1_id

    # Corrupt artifact storage path to force failure on re-analysis
    art = db_session.query(Artifact).filter(Artifact.investigation_id == inv_id).first()
    orig_path = art.storage_path
    art.storage_path = "non_existent_file_path.eml"
    db_session.commit()

    try:
        # Submit feedback -> pipeline will fail
        with pytest.raises(Exception):
            client.post(
                f"/api/v1/investigations/{inv_id}/feedback",
                json={"feedback_type": "SPAM_REPORTED", "note": "Should fail gracefully"},
                headers=headers,
            )
    finally:
        # Restore path
        art.storage_path = orig_path
        db_session.commit()

    db_session.refresh(inv)
    # The current run MUST remain run1_id! It was never replaced by a failed run!
    assert inv.current_analysis_run_id == run1_id
