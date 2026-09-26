from dataclasses import dataclass

from app.services.score_engine import compute_score, STRENGTH_POINTS, CATEGORY_CAPS, severity_for_score
from tests.conftest import auth_headers, create_investigation, create_run, internal_service_headers


@dataclass
class _FakeFinding:
    id: str
    category: str
    strength: str
    qualification_code: str = "FINANCIAL_REQUEST"


def test_strength_point_constants_locked():
    assert STRENGTH_POINTS["Weak"] == 0.5
    assert STRENGTH_POINTS["Moderate"] == 1.0
    assert STRENGTH_POINTS["Strong"] == 1.5


def test_category_caps_locked():
    assert CATEGORY_CAPS == {
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


def test_severity_boundaries():
    assert severity_for_score(0) == "LOW"
    assert severity_for_score(29) == "LOW"
    assert severity_for_score(30) == "MEDIUM"
    assert severity_for_score(54) == "MEDIUM"
    assert severity_for_score(55) == "HIGH"
    assert severity_for_score(74) == "HIGH"
    assert severity_for_score(75) == "CRITICAL"
    assert severity_for_score(100) == "CRITICAL"


def test_category_cap_applied():
    # FINANCIAL_REQUEST (Social Engineering) base weight 8.
    # Three Strong (8 * 1.5 = 12 each = 36 raw) in Social Engineering, cap is 14.
    findings = [_FakeFinding(id=f"f{i}", category="Social Engineering", strength="Strong", qualification_code="FINANCIAL_REQUEST") for i in range(3)]
    result = compute_score(findings)
    assert result.category_breakdown["Social Engineering"] == 14
    assert result.total_score == 8  # round(14 / 166 * 100) = 8


def test_global_cap_applied():
    findings = [
        _FakeFinding(id="f1", category="Identity", strength="Strong", qualification_code="EXECUTIVE_IMPERSONATION"),
        _FakeFinding(id="f2", category="Domain", strength="Strong", qualification_code="HOMOGLYPH_DOMAIN_MATCH"),
        _FakeFinding(id="f2b", category="Domain", strength="Strong", qualification_code="MIXED_SCRIPT_DOMAIN"),
        _FakeFinding(id="f3", category="URL", strength="Strong", qualification_code="CREDENTIAL_PHISHING_LINK"),
        _FakeFinding(id="f4", category="Attachment", strength="Strong", qualification_code="EXECUTABLE_IN_ARCHIVE"),
        _FakeFinding(id="f5", category="Routing", strength="Strong", qualification_code="ROUTING_FABRICATION_QUALIFIED"),
        _FakeFinding(id="f6", category="Threat Intelligence", strength="Strong", qualification_code="CONFIRMED_MALICIOUS_INDICATOR"),
        _FakeFinding(id="f7", category="Authentication", strength="Strong", qualification_code="DMARC_FAIL"),
        _FakeFinding(id="f7b", category="Authentication", strength="Strong", qualification_code="SPF_FAIL"),
        _FakeFinding(id="f8", category="Infrastructure", strength="Strong", qualification_code="BULLETPROOF_HOSTING_MATCH"),
        _FakeFinding(id="f8b", category="Infrastructure", strength="Strong", qualification_code="KNOWN_BAD_ASN"),
        _FakeFinding(id="f9", category="Social Engineering", strength="Strong", qualification_code="FINANCIAL_REQUEST"),
        _FakeFinding(id="f9b", category="Social Engineering", strength="Moderate", qualification_code="FINANCIAL_REQUEST"),
    ]
    result = compute_score(findings)
    assert result.total_score == 100


def test_clean_authentication_contributes_zero_not_negative():
    findings = []  # no Authentication findings at all
    result = compute_score(findings)
    assert result.category_breakdown["Authentication"] == 0
    assert result.total_score == 0
    assert result.severity == "LOW"


def test_weak_finding_alone_does_not_trigger_a_floor():
    findings = [
        _FakeFinding(id="f1", category="Identity", strength="Weak", qualification_code="EXECUTIVE_IMPERSONATION"),
        _FakeFinding(id="f2", category="Social Engineering", strength="Weak", qualification_code="FINANCIAL_REQUEST"),
    ]
    result = compute_score(findings)
    assert "CF-02" not in result.triggered_floor_codes


def test_moderate_pair_triggers_cf02_floor_and_forces_high_severity():
    findings = [
        _FakeFinding(id="f1", category="Identity", strength="Moderate", qualification_code="EXECUTIVE_IMPERSONATION"),
        _FakeFinding(id="f2", category="Social Engineering", strength="Moderate", qualification_code="FINANCIAL_REQUEST"),
    ]
    result = compute_score(findings)
    assert "CF-02" in result.triggered_floor_codes
    assert result.severity == "HIGH"


# --------------------------------------------------------- API integration --

def _create_deterministic_finding(client, user, inv_id, run_id, **overrides):
    body = {
        "category": "Content",
        "qualification_code": "FINANCIAL_REQUEST",
        "qualification_version": "reg-v1",
        "strength": "Moderate",
        "analysis_run_id": run_id,
        "normalized_subject_or_target": "target-1",
        "claim_signature": "payment_transfer_request",
        "supporting_fact_ids": [],
        "supporting_text": "some grounded text",
        "produced_by": "deterministic",
    }
    body.update(overrides)
    return client.post(f"/api/v1/investigations/{inv_id}/findings", json=body, headers=internal_service_headers(user))


def _advance_run_to_scoring(client, user, inv_id, run_id):
    for target in ("PARSING", "ANALYZING", "SCORING"):
        client.post(
            f"/api/v1/investigations/{inv_id}/analysis-runs/{run_id}/status",
            json={"status": target}, headers=auth_headers(user),
        )


def test_score_endpoint_computes_from_findings_not_caller_input(client, user):
    inv = create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    create_resp = _create_deterministic_finding(client, user, inv["id"], run_id=run["id"])
    assert create_resp.status_code == 201, create_resp.json()
    _advance_run_to_scoring(client, user, inv["id"], run["id"])

    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/score",
        headers=auth_headers(user),
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["total_score"] == 5  # one Moderate FINANCIAL_REQUEST (Social Engineering) finding: round(8/166*100) = 5
    assert body["severity"] == "LOW"  # 5 <= 29
    assert body["category_breakdown"]["Social Engineering"] == 8


def test_score_endpoint_rejects_second_computation_for_same_run(client, user):
    inv = create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    _create_deterministic_finding(client, user, inv["id"], run_id=run["id"])
    _advance_run_to_scoring(client, user, inv["id"], run["id"])

    first = client.post(
        f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/score",
        headers=auth_headers(user),
    )
    assert first.status_code == 201

    second = client.post(
        f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/score",
        headers=auth_headers(user),
    )
    assert second.status_code == 409


def test_score_engine_strictly_isolates_runs(client, user):
    """P0 #2 regression test: score engine evaluates ONLY findings from current run."""
    inv = create_investigation(client, user)
    run1 = create_run(client, user, inv["id"])
    run2 = create_run(client, user, inv["id"])
    run3 = create_run(client, user, inv["id"])

    # Run 1 has 18 pts
    _create_deterministic_finding(client, user, inv["id"], run_id=run1["id"], strength="Moderate")
    # Run 2 has 30 pts
    _create_deterministic_finding(
        client, user, inv["id"], run_id=run2["id"],
        category="Identity", qualification_code="EXECUTIVE_IMPERSONATION",
        claim_signature="executive_display_name_claim", strength="Strong",
    )
    # Run 3 has no findings

    _advance_run_to_scoring(client, user, inv["id"], run1["id"])
    _advance_run_to_scoring(client, user, inv["id"], run2["id"])
    _advance_run_to_scoring(client, user, inv["id"], run3["id"])

    r1_score = client.post(f"/api/v1/investigations/{inv['id']}/analysis-runs/{run1['id']}/score", headers=auth_headers(user))
    r2_score = client.post(f"/api/v1/investigations/{inv['id']}/analysis-runs/{run2['id']}/score", headers=auth_headers(user))
    r3_score = client.post(f"/api/v1/investigations/{inv['id']}/analysis-runs/{run3['id']}/score", headers=auth_headers(user))

    assert r1_score.status_code == 201
    assert r1_score.json()["total_score"] == 5
    assert r2_score.status_code == 201
    assert r2_score.json()["total_score"] == 12
    assert r3_score.status_code == 201
    assert r3_score.json()["total_score"] == 0
    assert r3_score.json()["severity"] == "LOW"


def test_score_endpoint_rejects_queued_run(client, user):
    inv = create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/score",
        headers=auth_headers(user),
    )
    assert resp.status_code == 409


def test_score_endpoint_has_no_request_body_fields_for_score_values():
    """
    Static/documentation-level check: the route function takes no
    Pydantic body model at all for POST .../score (see
    app/api/v1/routes_findings.py) -- there is no schema a caller could
    populate with total_score/severity/triggered_floor_codes even if
    they wanted to.
    """
    import inspect
    from app.api.v1.routes_findings import compute_score as compute_score_route

    sig = inspect.signature(compute_score_route)
    param_names = list(sig.parameters.keys())
    assert "body" not in param_names
