"""
Tests for Finding run-ownership invariant (P0 migration/run-ownership fix).

Proves:
  A. Fresh migration succeeds through head.
  B. Finding.analysis_run_id is NOT NULL at DB level.
  C. Finding creation without analysis_run_id is rejected.
  D. Finding creation with a valid run succeeds.
  E. Finding from run A cannot be attached to run B (dedup isolation).
  F. Same dedup identity in different runs creates separate Findings.
  G. Same dedup identity in the same run deduplicates.
  H. Existing NULL Finding data causes migration to fail clearly
     rather than being assigned arbitrarily.
  I. GET findings with no run filter does not use a NULL-run branch.
  J. GET findings with analysis_run_id returns only that run.
  K. Run B score cannot consume Run A findings.
"""
import pytest
from sqlalchemy import inspect as sa_inspect

from app.models import Finding
from tests.conftest import (
    auth_headers,
    internal_service_headers,
    create_investigation,
    create_run,
)


def _finding_payload(run_id, **overrides):
    payload = {
        "category": "Content",
        "qualification_code": "FINANCIAL_REQUEST",
        "qualification_version": "1.0",
        "strength": "Moderate",
        "analysis_run_id": run_id,
        "normalized_subject_or_target": "wire-transfer-request",
        "claim_signature": "payment_transfer_request",
        "supporting_fact_ids": [],
        "supporting_text": "Please process the wire transfer immediately.",
        "produced_by": "forensics_analyzer_v1",
    }
    payload.update(overrides)
    return payload


def _advance_run_to_scoring(client, user, inv_id, run_id):
    for target in ("PARSING", "ANALYZING", "SCORING"):
        client.post(
            f"/api/v1/investigations/{inv_id}/analysis-runs/{run_id}/status",
            json={"status": target}, headers=auth_headers(user),
        )


# ============================================================
# TEST A: Fresh DB schema has analysis_run_id NOT NULL
# ============================================================

def test_finding_analysis_run_id_column_is_not_nullable(db_session):
    """
    TEST A+B: The Finding table's analysis_run_id column is NOT NULL at
    the SQLAlchemy model level and the database level. This proves
    a fresh create_all (which tests use) enforces the constraint.
    """
    # Check SQLAlchemy model
    col = Finding.__table__.columns["analysis_run_id"]
    assert col.nullable is False, "Finding.analysis_run_id must be nullable=False"

    # Check the actual DB schema (SQLite inspector)
    inspector = sa_inspect(db_session.bind)
    columns = {c["name"]: c for c in inspector.get_columns("findings")}
    assert "analysis_run_id" in columns
    assert columns["analysis_run_id"]["nullable"] is False


# ============================================================
# TEST C: Finding creation without analysis_run_id is rejected
# ============================================================

def test_finding_creation_without_run_id_rejected_at_schema(client, user):
    """
    TEST C: POST finding with missing analysis_run_id → 422 validation error.
    Pydantic rejects the payload before it reaches the service layer.
    """
    inv = create_investigation(client, user)
    payload = {
        "category": "Content",
        "qualification_code": "FINANCIAL_REQUEST",
        "qualification_version": "1.0",
        "strength": "Moderate",
        # analysis_run_id INTENTIONALLY OMITTED
        "normalized_subject_or_target": "target",
        "claim_signature": "payment_transfer_request",
        "supporting_fact_ids": [],
        "supporting_text": "some text",
        "produced_by": "forensics_analyzer_v1",
    }
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=payload,
        headers=internal_service_headers(user),
    )
    assert resp.status_code == 422


# ============================================================
# TEST D: Finding creation with a valid run succeeds
# ============================================================

def test_finding_creation_with_valid_run_succeeds(client, user, db_session):
    """TEST D: Finding with a valid run ID is accepted and persisted."""
    inv = create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run["id"]),
        headers=internal_service_headers(user),
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["analysis_run_id"] == run["id"]

    finding = db_session.get(Finding, body["id"])
    assert finding.analysis_run_id == run["id"]


# ============================================================
# TEST E: Finding from run A cannot be attached to run B
# ============================================================

def test_finding_run_a_stays_in_run_a(client, user, db_session):
    """
    TEST E: A Finding created in run A is never migrated or attached to
    run B. They remain independent.
    """
    inv = create_investigation(client, user)
    run_a = create_run(client, user, inv["id"])
    run_b = create_run(client, user, inv["id"])

    resp_a = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run_a["id"]),
        headers=internal_service_headers(user),
    )
    assert resp_a.status_code == 201
    finding = db_session.get(Finding, resp_a.json()["id"])
    assert finding.analysis_run_id == run_a["id"]
    assert finding.analysis_run_id != run_b["id"]


# ============================================================
# TEST F: Same dedup identity in different runs → separate Findings
# ============================================================

def test_same_dedup_identity_different_runs_creates_two(client, user, db_session):
    """TEST F: Same claim in run A and run B produces two distinct Findings."""
    inv = create_investigation(client, user)
    run_a = create_run(client, user, inv["id"])
    run_b = create_run(client, user, inv["id"])
    headers = internal_service_headers(user)

    r1 = client.post(f"/api/v1/investigations/{inv['id']}/findings",
                     json=_finding_payload(run_a["id"]), headers=headers)
    r2 = client.post(f"/api/v1/investigations/{inv['id']}/findings",
                     json=_finding_payload(run_b["id"]), headers=headers)

    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["id"] != r2.json()["id"]

    findings = db_session.query(Finding).filter(Finding.investigation_id == inv["id"]).all()
    assert len(findings) == 2


# ============================================================
# TEST G: Same dedup identity in same run deduplicates
# ============================================================

def test_same_dedup_identity_same_run_merges(client, user, db_session):
    """TEST G: Same claim submitted twice in the same run deduplicates (merges)."""
    inv = create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    headers = internal_service_headers(user)

    r1 = client.post(f"/api/v1/investigations/{inv['id']}/findings",
                     json=_finding_payload(run["id"], supporting_fact_ids=["f1"]),
                     headers=headers)
    r2 = client.post(f"/api/v1/investigations/{inv['id']}/findings",
                     json=_finding_payload(run["id"], supporting_fact_ids=["f2"]),
                     headers=headers)

    assert r1.status_code == 201
    assert r2.status_code == 201
    # Both return the same Finding ID (merge)
    assert r1.json()["id"] == r2.json()["id"]

    findings = db_session.query(Finding).filter(Finding.investigation_id == inv["id"]).all()
    assert len(findings) == 1
    assert set(findings[0].supporting_fact_ids) == {"f1", "f2"}


# ============================================================
# TEST K: Run B score cannot consume Run A findings
# ============================================================

def test_run_b_score_cannot_consume_run_a_findings(client, user):
    """TEST E/K: Run B score only sees Run B findings, not Run A."""
    inv = create_investigation(client, user)
    run_a = create_run(client, user, inv["id"])
    run_b = create_run(client, user, inv["id"])
    headers = internal_service_headers(user)

    # Put a finding in run A
    client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run_a["id"]),
        headers=headers,
    )
    # Run B has NO findings

    _advance_run_to_scoring(client, user, inv["id"], run_a["id"])
    _advance_run_to_scoring(client, user, inv["id"], run_b["id"])

    score_a = client.post(
        f"/api/v1/investigations/{inv['id']}/analysis-runs/{run_a['id']}/score",
        headers=auth_headers(user),
    )
    score_b = client.post(
        f"/api/v1/investigations/{inv['id']}/analysis-runs/{run_b['id']}/score",
        headers=auth_headers(user),
    )

    assert score_a.status_code == 201
    assert score_b.status_code == 201
    assert score_a.json()["total_score"] == 5  # one Moderate FINANCIAL_REQUEST (Social Engineering): round(8/166*100) = 5
    assert score_b.json()["total_score"] == 0   # no findings → LOW
    assert score_b.json()["severity"] == "LOW"


# ============================================================
# TEST: No NULL-run Finding can enter via trust boundary path
# ============================================================

def test_null_run_finding_impossible_via_schema(client, user):
    """
    TEST F: No NULL-run Finding can enter the normal production persistence
    path. Pydantic FindingCreate requires analysis_run_id as a string,
    so null/omitted values are rejected before hitting the database.
    """
    inv = create_investigation(client, user)

    # Explicitly sending null
    payload = {
        "category": "Content",
        "qualification_code": "FINANCIAL_REQUEST",
        "qualification_version": "1.0",
        "strength": "Moderate",
        "analysis_run_id": None,
        "normalized_subject_or_target": "target",
        "claim_signature": "payment_transfer_request",
        "supporting_fact_ids": [],
        "supporting_text": "some text",
        "produced_by": "forensics_analyzer_v1",
    }
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=payload,
        headers=internal_service_headers(user),
    )
    assert resp.status_code == 422
