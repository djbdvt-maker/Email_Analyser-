from app.models import Finding, AnalysisRun
from tests.conftest import auth_headers, internal_service_headers, create_run


def _create_investigation(client, user):
    resp = client.post("/api/v1/investigations", json={"title": "Test"}, headers=auth_headers(user))
    return resp.json()


def _finding_payload(analysis_run_id, **overrides):
    payload = {
        "category": "Content",
        "qualification_code": "FINANCIAL_REQUEST",
        "qualification_version": "1.0",
        "strength": "Moderate",
        "analysis_run_id": analysis_run_id,
        "normalized_subject_or_target": "wire-transfer-request",
        "claim_signature": "payment_transfer_request",
        "supporting_fact_ids": ["fact-1"],
        "supporting_text": "Please process the wire transfer immediately.",
        "produced_by": "forensics_analyzer_v1",
    }
    payload.update(overrides)
    return payload


def test_finding_created(client, user):
    inv = _create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run["id"]),
        headers=internal_service_headers(user),
    )
    assert resp.status_code == 201, resp.json()
    assert resp.json()["strength"] == "Moderate"
    assert resp.json()["analysis_run_id"] == run["id"]


def test_duplicate_claim_merges_evidence_not_strength(client, user, db_session):
    inv = _create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    headers = internal_service_headers(user)

    first = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run["id"], supporting_fact_ids=["fact-1"], strength="Moderate"),
        headers=headers,
    )
    assert first.status_code == 201, first.json()

    # Same dedup key (category, qualification_code, claim_signature,
    # normalized target), a different analyzer, and a HIGHER strength.
    second = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(
            run["id"],
            supporting_fact_ids=["fact-2"],
            strength="Strong",
            produced_by="forensics_analyzer_v2",
        ),
        headers=headers,
    )
    assert second.status_code == 201, second.json()

    findings = db_session.query(Finding).filter(Finding.investigation_id == inv["id"]).all()
    assert len(findings) == 1  # merged, not duplicated

    merged = findings[0]
    assert set(merged.supporting_fact_ids) == {"fact-1", "fact-2"}
    # The critical invariant: two Moderate/Strong corroborating
    # observations of the SAME claim never auto-upgrade strength.
    assert merged.strength == "Moderate"


def test_distinct_claim_signature_is_not_merged(client, user, db_session):
    inv = _create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    headers = internal_service_headers(user)

    r1 = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run["id"], claim_signature="payment_transfer_request"),
        headers=headers,
    )
    r2 = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run["id"], claim_signature="invoice_change_request"),
        headers=headers,
    )
    assert r1.status_code == 201, r1.json()
    assert r2.status_code == 201, r2.json()

    findings = db_session.query(Finding).filter(Finding.investigation_id == inv["id"]).all()
    assert len(findings) == 2


def test_list_findings_org_scoped(client, user, other_org_user, db_session):
    inv = _create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run["id"]),
        headers=internal_service_headers(user),
    )
    resp = client.get(f"/api/v1/investigations/{inv['id']}/findings", headers=auth_headers(other_org_user))
    assert resp.status_code == 404


def test_direct_finding_creation_requires_internal_service_key(client, user):
    """
    A valid user JWT alone (no X-Internal-Service-Key) must NOT be
    enough to create a Finding directly -- see
    tests/test_internal_service_key.py for the dedicated suite. This
    is a light smoke-test reminder living alongside the dedup tests.
    """
    inv = _create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run["id"]),
        headers=auth_headers(user),
    )
    assert resp.status_code == 403


def test_analyzer_strength_cannot_exceed_maximum_strength(client, user, db_session):
    """
    Asserts that analyzer-provided strength cannot exceed the qualification's
    registered maximum_strength ceiling. If an analyzer attempts Strong
    for a qualification capped at Weak (e.g. GENERIC_SUSPICION), the backend clamps it to Weak.
    """
    inv = _create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    headers = internal_service_headers(user)

    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(
            run["id"],
            qualification_code="GENERIC_SUSPICION",
            claim_signature="generic_suspicious_content",
            strength="Strong",
        ),
        headers=headers,
    )
    assert resp.status_code == 201, resp.json()
    finding_id = resp.json()["id"]

    finding = db_session.get(Finding, finding_id)
    assert finding.strength == "Weak", f"Expected clamped strength Weak, got {finding.strength}"


def test_deduplication_is_run_scoped(client, user, db_session):
    """
    P0 #1 regression test: identical findings in DIFFERENT runs must NOT merge.
    Identical findings within the SAME run MUST merge.
    """
    inv = _create_investigation(client, user)
    headers = internal_service_headers(user)
    run1 = create_run(client, user, inv["id"])
    run2 = create_run(client, user, inv["id"])

    # Finding in Run 1
    r1 = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run1["id"], supporting_fact_ids=["fact-1"]),
        headers=headers,
    )
    assert r1.status_code == 201

    # Same claim in Run 2 (different run)
    r2 = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run2["id"], supporting_fact_ids=["fact-2"]),
        headers=headers,
    )
    assert r2.status_code == 201

    # Should have 2 distinct findings in the database (not merged across runs)
    findings = db_session.query(Finding).filter(Finding.investigation_id == inv["id"]).all()
    assert len(findings) == 2
    run_ids = {f.analysis_run_id for f in findings}
    assert run_ids == {run1["id"], run2["id"]}

    # A second submission in Run 1 SHOULD merge into Run 1's finding
    r3 = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run1["id"], supporting_fact_ids=["fact-3"]),
        headers=headers,
    )
    assert r3.status_code == 201

    findings_after = db_session.query(Finding).filter(Finding.investigation_id == inv["id"]).all()
    assert len(findings_after) == 2  # Still 2 findings total
    run1_finding = [f for f in findings_after if f.analysis_run_id == run1["id"]][0]
    assert set(run1_finding.supporting_fact_ids) == {"fact-1", "fact-3"}


def test_unknown_qualification_code_rejected(client, user):
    """P0 #3: unknown qualification codes must be rejected with 422, never auto-repaired."""
    inv = _create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run["id"], qualification_code="NON_EXISTENT_QUALIFICATION"),
        headers=internal_service_headers(user),
    )
    assert resp.status_code == 422
    err_body = resp.json()
    err_msg = err_body.get("message") or err_body.get("detail", "")
    assert "Unknown qualification_code" in err_msg


def test_invalid_claim_signature_rejected(client, user):
    """P0 #3: invalid claim signatures must be rejected with 422, never substituted."""
    inv = _create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(
            run["id"],
            qualification_code="FINANCIAL_REQUEST",
            claim_signature="completely_invented_signature",
        ),
        headers=internal_service_headers(user),
    )
    assert resp.status_code == 422
    err_body = resp.json()
    err_msg = err_body.get("message") or err_body.get("detail", "")
    assert "Invalid claim_signature" in err_msg


def test_category_scoring_bucket_max_strength_clamped(client, user, db_session):
    """
    P1 #5: Enforces category scoring_bucket max_strength.
    Authentication category is capped at Moderate in registry-v1.json.
    Even if an analyzer attempts Strong for SPF_FAIL, it must clamp to Moderate.
    """
    inv = _create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(
            run["id"],
            category="Authentication",
            qualification_code="SPF_FAIL",
            claim_signature="spf_validation_fail",
            strength="Strong",
        ),
        headers=internal_service_headers(user),
    )
    assert resp.status_code == 201, resp.json()
    finding_id = resp.json()["id"]

    finding = db_session.get(Finding, finding_id)
    assert finding.strength == "Moderate", f"Expected clamped strength Moderate, got {finding.strength}"


# ============================================================
# RUN-OWNERSHIP INVARIANT TESTS
# ============================================================


def test_finding_without_analysis_run_id_rejected(client, user):
    """
    TEST A: Normal Finding creation without analysis_run_id → rejected.
    No NULL-run Finding can enter the normal production persistence path.
    """
    inv = _create_investigation(client, user)
    payload = {
        "category": "Content",
        "qualification_code": "FINANCIAL_REQUEST",
        "qualification_version": "1.0",
        "strength": "Moderate",
        # analysis_run_id intentionally omitted
        "normalized_subject_or_target": "wire-transfer-request",
        "claim_signature": "payment_transfer_request",
        "supporting_fact_ids": [],
        "supporting_text": "Please process the wire transfer immediately.",
        "produced_by": "forensics_analyzer_v1",
    }
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=payload,
        headers=internal_service_headers(user),
    )
    assert resp.status_code == 422, f"Expected 422 for missing analysis_run_id, got {resp.status_code}: {resp.json()}"


def test_finding_with_run_a_gets_run_a(client, user, db_session):
    """TEST B: Finding with Run A → analysis_run_id = Run A."""
    inv = _create_investigation(client, user)
    run_a = create_run(client, user, inv["id"])
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run_a["id"]),
        headers=internal_service_headers(user),
    )
    assert resp.status_code == 201
    assert resp.json()["analysis_run_id"] == run_a["id"]

    finding = db_session.get(Finding, resp.json()["id"])
    assert finding.analysis_run_id == run_a["id"]


def test_finding_with_run_b_gets_run_b(client, user, db_session):
    """TEST C: Finding with Run B → analysis_run_id = Run B."""
    inv = _create_investigation(client, user)
    run_b = create_run(client, user, inv["id"])
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run_b["id"]),
        headers=internal_service_headers(user),
    )
    assert resp.status_code == 201
    assert resp.json()["analysis_run_id"] == run_b["id"]

    finding = db_session.get(Finding, resp.json()["id"])
    assert finding.analysis_run_id == run_b["id"]


def test_equivalent_finding_in_two_runs_creates_separate_findings(client, user, db_session):
    """TEST D: Equivalent Finding in Run A and Run B → two separate Findings."""
    inv = _create_investigation(client, user)
    run_a = create_run(client, user, inv["id"])
    run_b = create_run(client, user, inv["id"])
    headers = internal_service_headers(user)

    r1 = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run_a["id"]),
        headers=headers,
    )
    r2 = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run_b["id"]),
        headers=headers,
    )
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["id"] != r2.json()["id"]

    findings = db_session.query(Finding).filter(Finding.investigation_id == inv["id"]).all()
    assert len(findings) == 2
    assert {f.analysis_run_id for f in findings} == {run_a["id"], run_b["id"]}


def test_get_findings_no_run_filter_returns_all_not_null_branch(client, user, db_session):
    """
    TEST I: GET findings with no run filter does not use a NULL-run branch.
    It returns ALL findings across all runs for the investigation.
    """
    inv = _create_investigation(client, user)
    run_a = create_run(client, user, inv["id"])
    run_b = create_run(client, user, inv["id"])
    headers = internal_service_headers(user)

    client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run_a["id"]),
        headers=headers,
    )
    client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run_b["id"]),
        headers=headers,
    )

    # No analysis_run_id filter — should return ALL findings
    resp = client.get(
        f"/api/v1/investigations/{inv['id']}/findings",
        headers=auth_headers(user),
    )
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 2
    run_ids = {f["analysis_run_id"] for f in findings}
    assert run_ids == {run_a["id"], run_b["id"]}
    # Every returned finding has a non-null analysis_run_id
    for f in findings:
        assert f["analysis_run_id"] is not None


def test_get_findings_with_run_filter_returns_only_that_run(client, user, db_session):
    """TEST J: GET findings with analysis_run_id returns only that run."""
    inv = _create_investigation(client, user)
    run_a = create_run(client, user, inv["id"])
    run_b = create_run(client, user, inv["id"])
    headers = internal_service_headers(user)

    client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run_a["id"]),
        headers=headers,
    )
    client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run_b["id"]),
        headers=headers,
    )

    resp = client.get(
        f"/api/v1/investigations/{inv['id']}/findings?analysis_run_id={run_a['id']}",
        headers=auth_headers(user),
    )
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    assert findings[0]["analysis_run_id"] == run_a["id"]
