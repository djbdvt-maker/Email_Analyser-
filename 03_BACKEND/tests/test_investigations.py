from tests.conftest import auth_headers


def _create_investigation(client, user, title="Suspicious wire transfer email"):
    resp = client.post("/api/v1/investigations", json={"title": title}, headers=auth_headers(user))
    assert resp.status_code == 201
    return resp.json()


def test_create_and_get_investigation(client, user):
    inv = _create_investigation(client, user)
    assert inv["status"] == "AWAITING_ANALYSIS"
    assert inv["current_analysis_run_id"] is None

    resp = client.get(f"/api/v1/investigations/{inv['id']}", headers=auth_headers(user))
    assert resp.status_code == 200
    assert resp.json()["id"] == inv["id"]


def test_org_scoping_blocks_cross_org_access(client, user, other_org_user):
    inv = _create_investigation(client, user)

    resp = client.get(f"/api/v1/investigations/{inv['id']}", headers=auth_headers(other_org_user))
    assert resp.status_code == 404


def test_list_investigations_is_org_scoped(client, user, other_org_user):
    _create_investigation(client, user, title="Mine")
    _create_investigation(client, other_org_user, title="Theirs")

    resp = client.get("/api/v1/investigations", headers=auth_headers(user))
    titles = [i["title"] for i in resp.json()]
    assert titles == ["Mine"]


def test_valid_status_transition(client, user):
    inv = _create_investigation(client, user)
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/status",
        json={"status": "UNDER_REVIEW"},
        headers=auth_headers(user),
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "UNDER_REVIEW"


def test_invalid_status_transition_rejected(client, user):
    inv = _create_investigation(client, user)
    # Cannot jump straight from AWAITING_ANALYSIS to CONFIRMED
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/status",
        json={"status": "CONFIRMED"},
        headers=auth_headers(user),
    )
    assert resp.status_code == 409


def test_reopen_action_returns_to_under_review(client, user):
    inv = _create_investigation(client, user)
    headers = auth_headers(user)
    client.post(f"/api/v1/investigations/{inv['id']}/status", json={"status": "UNDER_REVIEW"}, headers=headers)
    client.post(f"/api/v1/investigations/{inv['id']}/status", json={"status": "FALSE_POSITIVE"}, headers=headers)

    resp = client.post(f"/api/v1/investigations/{inv['id']}/reopen", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "UNDER_REVIEW"


def test_no_reopened_status_value_exists(client, user):
    inv = _create_investigation(client, user)
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/status",
        json={"status": "REOPENED"},
        headers=auth_headers(user),
    )
    # REOPENED is not a valid enum value at all -- schema validation error.
    assert resp.status_code == 422


def test_perform_analyst_action(client, user):
    inv = _create_investigation(client, user)
    headers = auth_headers(user)
    # Move to UNDER_REVIEW first
    client.post(f"/api/v1/investigations/{inv['id']}/status", json={"status": "UNDER_REVIEW"}, headers=headers)

    # Perform confirm_malicious action
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/actions",
        json={"action": "confirm_malicious", "note": "Verified phishing attempt"},
        headers=headers,
    )
    assert resp.status_code == 200
    action_data = resp.json()
    assert action_data["action"] == "confirm_malicious"
    assert action_data["actor"] == user.email
    assert action_data["note"] == "Verified phishing attempt"

    # Check investigation status updated
    inv_resp = client.get(f"/api/v1/investigations/{inv['id']}", headers=headers)
    assert inv_resp.json()["status"] == "CONFIRMED"

    # Reopen action
    reopen_resp = client.post(
        f"/api/v1/investigations/{inv['id']}/actions",
        json={"action": "reopen", "note": "New evidence surfaced"},
        headers=headers,
    )
    assert reopen_resp.status_code == 200
    assert reopen_resp.json()["action"] == "reopen"

    # Check audit trail includes actions
    audit_resp = client.get(f"/api/v1/investigations/{inv['id']}/audit", headers=headers)
    assert audit_resp.status_code == 200
    audits = audit_resp.json()
    action_audits = [a for a in audits if a["action"] in ("INVESTIGATION_STATUS_CHANGED", "INVESTIGATION_REOPENED")]
    assert len(action_audits) >= 2
    actions = [a.get("metadata_json", a.get("metadata", {})).get("action") for a in action_audits]
    assert "confirm_malicious" in actions
    assert "reopen" in actions


