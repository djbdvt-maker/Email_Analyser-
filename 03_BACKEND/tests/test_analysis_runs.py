from tests.conftest import auth_headers


def _create_investigation(client, user):
    resp = client.post("/api/v1/investigations", json={"title": "Test"}, headers=auth_headers(user))
    return resp.json()


from tests.conftest import create_run as _create_run


def test_run_starts_queued(client, user):
    inv = _create_investigation(client, user)
    run = _create_run(client, user, inv["id"])
    assert run["status"] == "QUEUED"


def test_failed_run_does_not_become_current(client, user):
    headers = auth_headers(user)
    inv = _create_investigation(client, user)
    run = _create_run(client, user, inv["id"])

    for target in ("PARSING", "ANALYZING"):
        r = client.post(
            f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/status",
            json={"status": target}, headers=headers,
        )
        assert r.status_code == 200

    r = client.post(
        f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/status",
        json={"status": "FAILED", "failure_reason": "parser crashed"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "FAILED"

    inv_after = client.get(f"/api/v1/investigations/{inv['id']}", headers=headers).json()
    assert inv_after["current_analysis_run_id"] is None


def test_completed_run_becomes_current_and_survives_later_failure(client, user):
    headers = auth_headers(user)
    inv = _create_investigation(client, user)
    run1 = _create_run(client, user, inv["id"])

    for target in ("PARSING", "ANALYZING", "SCORING", "COMPLETED"):
        r = client.post(
            f"/api/v1/investigations/{inv['id']}/analysis-runs/{run1['id']}/status",
            json={"status": target}, headers=headers,
        )
        assert r.status_code == 200

    inv_after = client.get(f"/api/v1/investigations/{inv['id']}", headers=headers).json()
    assert inv_after["current_analysis_run_id"] == run1["id"]

    # A second run that fails must not replace the still-good current run.
    run2 = _create_run(client, user, inv["id"])
    client.post(
        f"/api/v1/investigations/{inv['id']}/analysis-runs/{run2['id']}/status",
        json={"status": "PARSING"}, headers=headers,
    )
    r = client.post(
        f"/api/v1/investigations/{inv['id']}/analysis-runs/{run2['id']}/status",
        json={"status": "FAILED", "failure_reason": "timeout"}, headers=headers,
    )
    assert r.status_code == 200

    inv_final = client.get(f"/api/v1/investigations/{inv['id']}", headers=headers).json()
    assert inv_final["current_analysis_run_id"] == run1["id"]


def test_no_set_current_run_endpoint_exists(client, user):
    inv = _create_investigation(client, user)
    run = _create_run(client, user, inv["id"])
    # There is deliberately no such route in the API.
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/set-current",
        headers=auth_headers(user),
    )
    assert resp.status_code == 404


def test_run_id_must_belong_to_path_investigation(client, user):
    headers = auth_headers(user)
    inv_a = _create_investigation(client, user)
    inv_b = _create_investigation(client, user)
    run_of_a = _create_run(client, user, inv_a["id"])

    # Same org, but the run belongs to inv_a, not inv_b.
    resp = client.get(
        f"/api/v1/investigations/{inv_b['id']}/analysis-runs/{run_of_a['id']}",
        headers=headers,
    )
    assert resp.status_code == 404


def test_invalid_transition_rejected(client, user):
    headers = auth_headers(user)
    inv = _create_investigation(client, user)
    run = _create_run(client, user, inv["id"])
    # Cannot go straight from QUEUED to COMPLETED
    r = client.post(
        f"/api/v1/investigations/{inv['id']}/analysis-runs/{run['id']}/status",
        json={"status": "COMPLETED"}, headers=headers,
    )
    assert r.status_code == 409


