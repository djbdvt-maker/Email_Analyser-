from app.config import get_settings
from app.security import INTERNAL_SERVICE_KEY_HEADER
from tests.conftest import auth_headers, internal_service_headers, TEST_INTERNAL_SERVICE_KEY, create_run


def _finding_payload(analysis_run_id):
    return {
        "category": "Content",
        "qualification_code": "FINANCIAL_REQUEST",
        "qualification_version": "1.0",
        "strength": "Moderate",
        "analysis_run_id": analysis_run_id,
        "normalized_subject_or_target": "wire-transfer-request",
        "claim_signature": "payment_transfer_request",
        "supporting_fact_ids": [],
        "supporting_text": "Please process the wire transfer immediately.",
        "produced_by": "forensics_analyzer_v1",
    }


def test_correct_key_plus_user_jwt_succeeds(client, user):
    inv = client.post("/api/v1/investigations", json={"title": "Test"}, headers=auth_headers(user)).json()
    run = create_run(client, user, inv["id"])
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run["id"]),
        headers=internal_service_headers(user),
    )
    assert resp.status_code == 201, resp.json()


def test_missing_header_rejected(client, user):
    """User JWT alone, with no X-Internal-Service-Key header at all, must not work."""
    inv = client.post("/api/v1/investigations", json={"title": "Test"}, headers=auth_headers(user)).json()
    run = create_run(client, user, inv["id"])
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run["id"]),
        headers=auth_headers(user),  # no internal key header
    )
    assert resp.status_code == 403


def test_wrong_key_rejected(client, user):
    inv = client.post("/api/v1/investigations", json={"title": "Test"}, headers=auth_headers(user)).json()
    run = create_run(client, user, inv["id"])
    headers = auth_headers(user)
    headers[INTERNAL_SERVICE_KEY_HEADER] = "definitely-the-wrong-key"
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run["id"]),
        headers=headers,
    )
    assert resp.status_code == 403


def test_self_declared_produced_by_no_longer_grants_trust_alone(client, user):
    """
    The old vulnerability: claiming a trusted-sounding produced_by
    string with no real credential must NOT be sufficient on its own.
    """
    inv = client.post("/api/v1/investigations", json={"title": "Test"}, headers=auth_headers(user)).json()
    run = create_run(client, user, inv["id"])
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run["id"]),  # produced_by="forensics_analyzer_v1", no key header
        headers=auth_headers(user),
    )
    assert resp.status_code == 403


def test_missing_server_configuration_rejects_even_with_a_key_supplied(client, user, monkeypatch):
    """
    Option-B behavior: if the server has no configured key at all, the
    trusted deterministic-producer path is unavailable -- even a caller
    who supplies *some* key value must be rejected, not accidentally
    let through by a bug like `expected == None` being true.
    """
    settings_obj = get_settings()
    monkeypatch.setattr(settings_obj, "hopzero_internal_service_key", None)

    inv = client.post("/api/v1/investigations", json={"title": "Test"}, headers=auth_headers(user)).json()
    run = create_run(client, user, inv["id"])
    headers = auth_headers(user)
    headers[INTERNAL_SERVICE_KEY_HEADER] = "anything-at-all"
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings",
        json=_finding_payload(run["id"]),
        headers=headers,
    )
    assert resp.status_code == 403


def test_missing_config_and_wrong_key_are_externally_indistinguishable(client, user, monkeypatch):
    """
    The caller must not be able to tell "server isn't configured for
    this" apart from "your key is wrong" from the response alone.
    """
    inv = client.post("/api/v1/investigations", json={"title": "Test"}, headers=auth_headers(user)).json()
    run = create_run(client, user, inv["id"])

    wrong_key_headers = auth_headers(user)
    wrong_key_headers[INTERNAL_SERVICE_KEY_HEADER] = "wrong-key"
    wrong_key_resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings", json=_finding_payload(run["id"]), headers=wrong_key_headers,
    )

    settings_obj = get_settings()
    monkeypatch.setattr(settings_obj, "hopzero_internal_service_key", None)
    no_config_headers = auth_headers(user)
    no_config_headers[INTERNAL_SERVICE_KEY_HEADER] = "wrong-key"
    no_config_resp = client.post(
        f"/api/v1/investigations/{inv['id']}/findings", json=_finding_payload(run["id"]), headers=no_config_headers,
    )

    assert wrong_key_resp.status_code == no_config_resp.status_code == 403
    assert wrong_key_resp.json() == no_config_resp.json()


def test_no_hardcoded_fallback_secret_in_source():
    """
    Static/documentation-level check: there is no literal fallback
    secret string anywhere in app/config.py or app/security.py. The
    only acceptable non-None value for hopzero_internal_service_key
    comes from the environment.
    """
    import inspect
    from app import config, security

    config_source = inspect.getsource(config)
    security_source = inspect.getsource(security)
    for suspicious in ("hopzero-internal-service-secret-key", "internal-service-secret"):
        assert suspicious not in config_source
        assert suspicious not in security_source
