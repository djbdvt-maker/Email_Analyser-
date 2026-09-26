from app.models import Fact, Finding, ScoreConclusion, AICandidate
from tests.conftest import (
    auth_headers, create_investigation, create_run, create_source_fact,
    create_ai_execution, submit_ai_candidate,
)


def _setup(client, user):
    inv = create_investigation(client, user)
    run = create_run(client, user, inv["id"])
    execution = create_ai_execution(client, user, inv["id"], run["id"])
    return inv, run, execution


def test_unknown_qualification_rejected(client, user, db_session):
    inv, run, execution = _setup(client, user)
    fact = create_source_fact(client, user, inv["id"], run["id"], "Please wire $5,000 to account 123456789.")

    resp = submit_ai_candidate(
        client, user, inv["id"], run["id"],
        qualification_code="TOTALLY_MADE_UP_CODE",
        claim_signature="payment_transfer_request",
        supporting_text="wire $5,000",
        source_fact_id=fact["id"],
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "REJECTED"
    assert body["rejection_stage"] == "qualification_validation"
    assert body["resulting_finding_id"] is None
    assert db_session.query(Finding).count() == 0


def test_unknown_qualification_not_remapped_to_generic_suspicion(client, user, db_session):
    inv, run, execution = _setup(client, user)
    fact = create_source_fact(client, user, inv["id"], run["id"], "Please wire $5,000 to account 123456789.")

    resp = submit_ai_candidate(
        client, user, inv["id"], run["id"],
        qualification_code="NOT_A_REAL_CODE", source_fact_id=fact["id"],
    )
    body = resp.json()
    assert body["qualification_code"] == "NOT_A_REAL_CODE"  # never silently rewritten
    findings = db_session.query(Finding).filter(Finding.qualification_code == "GENERIC_SUSPICION").all()
    assert findings == []


def test_invalid_claim_signature_rejected(client, user, db_session):
    inv, run, execution = _setup(client, user)
    fact = create_source_fact(client, user, inv["id"], run["id"], "Please wire $5,000 to account 123456789.")

    resp = submit_ai_candidate(
        client, user, inv["id"], run["id"],
        qualification_code="FINANCIAL_REQUEST",
        claim_signature="totally_made_up_signature",
        supporting_text="wire $5,000",
        source_fact_id=fact["id"],
    )
    body = resp.json()
    assert body["status"] == "REJECTED"
    assert body["rejection_stage"] == "claim_signature_validation"


def test_not_grounded_rejected(client, user):
    inv, run, execution = _setup(client, user)
    fact = create_source_fact(client, user, inv["id"], run["id"], "Please wire $5,000 to account 123456789.")

    resp = submit_ai_candidate(
        client, user, inv["id"], run["id"],
        supporting_text="this text does not appear in the source at all",
        source_fact_id=fact["id"],
    )
    body = resp.json()
    assert body["status"] == "REJECTED"
    assert body["rejection_stage"] == "grounding_validation"


def test_h2_context_stripping_rejected_not_downgraded(client, user, db_session):
    """
    The exact H2 example from the corrections doc: grounding passes
    (the substring is really there) but the surrounding sentence is
    discussing/testing the concept, not making the request. Expected:
    REJECTED, with NO Weak/Moderate fallback Finding created.
    """
    inv, run, execution = _setup(client, user)
    source_text = (
        "The security team is testing whether employees can recognize "
        "requests to transfer funds."
    )
    fact = create_source_fact(client, user, inv["id"], run["id"], source_text)

    resp = submit_ai_candidate(
        client, user, inv["id"], run["id"],
        qualification_code="FINANCIAL_REQUEST",
        claim_signature="payment_transfer_request",
        supporting_text="requests to transfer funds",
        source_fact_id=fact["id"],
    )
    body = resp.json()
    assert body["status"] == "REJECTED"
    assert body["rejection_stage"] == "validity_requirements"
    assert body["resulting_finding_id"] is None
    assert db_session.query(Finding).count() == 0


def test_deterministic_strength_overrides_model_suggestion(client, user, db_session):
    """
    A genuine, valid FINANCIAL_REQUEST claim that does NOT satisfy the
    Strong strength-rule predicates (no explicit payment verb/monetary
    amount in the local window) must persist at the registry's
    default_strength (Moderate), even though the model suggested
    Strong. model_suggested_strength is telemetry only.
    """
    inv, run, execution = _setup(client, user)
    source_text = (
        "Hi team, please process this request regarding funds for the "
        "new vendor onboarding this week."
    )
    fact = create_source_fact(client, user, inv["id"], run["id"], source_text)

    resp = submit_ai_candidate(
        client, user, inv["id"], run["id"],
        qualification_code="FINANCIAL_REQUEST",
        claim_signature="payment_transfer_request",
        supporting_text="request regarding funds for the new vendor",
        source_fact_id=fact["id"],
        model_suggested_strength="Strong",
    )
    body = resp.json()
    assert body["status"] == "ACCEPTED"
    assert body["model_suggested_strength"] == "Strong"  # preserved as telemetry

    finding = db_session.get(Finding, body["resulting_finding_id"])
    assert finding.strength == "Moderate"  # deterministic default, NOT the model's Strong


def test_strength_rule_upgrades_when_predicates_satisfied(client, user, db_session):
    inv, run, execution = _setup(client, user)
    source_text = "Please wire $5,000 immediately to account 987654321 to close this out today."
    fact = create_source_fact(client, user, inv["id"], run["id"], source_text)

    resp = submit_ai_candidate(
        client, user, inv["id"], run["id"],
        qualification_code="FINANCIAL_REQUEST",
        claim_signature="payment_transfer_request",
        supporting_text="wire $5,000 immediately to account 987654321",
        source_fact_id=fact["id"],
        model_suggested_strength=None,
    )
    body = resp.json()
    assert body["status"] == "ACCEPTED"
    finding = db_session.get(Finding, body["resulting_finding_id"])
    assert finding.strength == "Strong"


def test_ai_candidate_cannot_directly_create_a_score(client, user, db_session):
    inv, run, execution = _setup(client, user)
    fact = create_source_fact(client, user, inv["id"], run["id"], "Please wire $5,000 to account 123456789.")
    submit_ai_candidate(
        client, user, inv["id"], run["id"],
        supporting_text="wire $5,000 to account 123456789",
        source_fact_id=fact["id"],
    )
    # No ScoreConclusion exists until the separate, backend-computed
    # /score endpoint is called -- and AICandidateCreate has no field
    # for total_score/severity/floors even if a caller tried to send one.
    assert db_session.query(ScoreConclusion).count() == 0


def test_ai_candidate_schema_has_no_score_or_severity_fields(client, user):
    inv, run, execution = _setup(client, user)
    fact = create_source_fact(client, user, inv["id"], run["id"], "Please wire $5,000 to account 123456789.")

    resp = submit_ai_candidate(
        client, user, inv["id"], run["id"],
        supporting_text="wire $5,000 to account 123456789",
        source_fact_id=fact["id"],
    )
    body = resp.json()
    assert "total_score" not in body
    assert "severity" not in body
    assert "triggered_floor_codes" not in body


def test_rejected_candidate_cannot_be_stored_as_a_fact(client, user, db_session):
    inv, run, execution = _setup(client, user)
    fact = create_source_fact(client, user, inv["id"], run["id"], "Please wire $5,000 to account 123456789.")
    facts_before = db_session.query(Fact).count()

    submit_ai_candidate(
        client, user, inv["id"], run["id"],
        qualification_code="NOT_A_REAL_CODE",
        source_fact_id=fact["id"],
    )

    facts_after = db_session.query(Fact).count()
    assert facts_after == facts_before  # rejected candidate created no new Fact


def test_accepted_candidate_also_creates_no_new_fact(client, user, db_session):
    inv, run, execution = _setup(client, user)
    fact = create_source_fact(client, user, inv["id"], run["id"], "Please wire $5,000 to account 123456789.")
    facts_before = db_session.query(Fact).count()

    submit_ai_candidate(
        client, user, inv["id"], run["id"],
        supporting_text="wire $5,000 to account 123456789",
        source_fact_id=fact["id"],
    )

    facts_after = db_session.query(Fact).count()
    assert facts_after == facts_before  # an accepted AI semantic candidate is a Finding, never a Fact


def test_every_submission_is_persisted_for_audit(client, user, db_session):
    inv, run, execution = _setup(client, user)
    fact = create_source_fact(client, user, inv["id"], run["id"], "Please wire $5,000 to account 123456789.")

    submit_ai_candidate(client, user, inv["id"], run["id"], qualification_code="NOT_A_REAL_CODE",
                         source_fact_id=fact["id"])
    submit_ai_candidate(client, user, inv["id"], run["id"], supporting_text="wire $5,000 to account 123456789",
                         source_fact_id=fact["id"])

    assert db_session.query(AICandidate).count() == 2


def test_second_ai_execution_for_same_run_rejected(client, user):
    inv, run, execution = _setup(client, user)
    resp = create_ai_execution(client, user, inv["id"], run["id"])
    # helper returns .json() of the response; check via raw client instead
    from tests.conftest import auth_headers as _ah
    resp2 = client.post(
        f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/ai-execution",
        json={
            "model_identifier": "test-model-2",
            "model_version_or_digest": "sha256:cafebabe",
            "prompt_schema_version": "prompt-v1",
            "deterministic_context_snapshot_hash": "sha256:different",
            "ai_generation_parameters": {},
        },
        headers=_ah(user),
    )
    assert resp2.status_code == 409


def test_fake_supporting_fact_rejected(client, user):
    """A fake or non-existent source_fact_id must be hard-rejected with HTTP 400."""
    inv, run, execution = _setup(client, user)
    from tests.conftest import auth_headers as _ah

    # Non-existent fact ID
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/ai-candidates",
        json={
            "qualification_code": "FINANCIAL_REQUEST",
            "claim_signature": "payment_transfer_request",
            "supporting_text": "wire $5,000",
            "source_fact_id": "non-existent-fact-id-12345",
            "model_suggested_strength": "Moderate",
        },
        headers=_ah(user),
    )
    assert resp.status_code == 400
    assert "does not reference a Fact in this investigation" in resp.json()["message"]


def test_cross_investigation_fact_rejected(client, user):
    """A source_fact_id from another investigation must be hard-rejected with HTTP 400."""
    inv1, run1, execution1 = _setup(client, user)
    inv2, run2, execution2 = _setup(client, user)
    fact2 = create_source_fact(client, user, inv2["id"], run2["id"], "Please wire $5,000 to account 123456789.")
    from tests.conftest import auth_headers as _ah

    resp = client.post(
        f"/api/v1/investigations/{inv1['id']}/analysis-runs/{run1['id']}/ai-candidates",
        json={
            "qualification_code": "FINANCIAL_REQUEST",
            "claim_signature": "payment_transfer_request",
            "supporting_text": "wire $5,000",
            "source_fact_id": fact2["id"],
            "model_suggested_strength": "Moderate",
        },
        headers=_ah(user),
    )
    assert resp.status_code == 400
    assert "does not reference a Fact in this investigation" in resp.json()["message"]


def test_disallowed_ai_qualification_rejected(client, user, db_session):
    """Qualifications where ai_eligible=False must be rejected at qualification_validation."""
    inv, run, execution = _setup(client, user)
    fact = create_source_fact(client, user, inv["id"], run["id"], "Authentication failed from SPF and DKIM.")

    # SPF_FAIL is deterministic only (ai_eligible = False)
    resp = submit_ai_candidate(
        client, user, inv["id"], run["id"],
        qualification_code="SPF_FAIL",
        claim_signature="spf_hardfail",
        supporting_text="Authentication failed from SPF",
        source_fact_id=fact["id"],
    )
    body = resp.json()
    assert body["status"] == "REJECTED"
    assert body["rejection_stage"] == "qualification_validation"
    assert "not AI-eligible" in body["rejection_reason"]
    assert db_session.query(Finding).count() == 0


def test_strength_above_registry_maximum_clamped(client, user, db_session):
    """
    GENERIC_SUSPICION has maximum_strength='Weak'. If the model suggests 'Strong',
    the trust boundary clamps deterministic strength to 'Weak' and never exceeds it.
    """
    inv, run, execution = _setup(client, user)
    source_text = "This email looks suspicious and unusual."
    fact = create_source_fact(client, user, inv["id"], run["id"], source_text)

    resp = submit_ai_candidate(
        client, user, inv["id"], run["id"],
        qualification_code="GENERIC_SUSPICION",
        claim_signature="generic_suspicious_content",
        supporting_text="suspicious and unusual",
        source_fact_id=fact["id"],
        model_suggested_strength="Strong",
    )
    body = resp.json()
    assert body["status"] == "ACCEPTED"
    finding = db_session.get(Finding, body["resulting_finding_id"])
    assert finding.strength == "Weak"

