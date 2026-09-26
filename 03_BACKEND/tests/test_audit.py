from app.main import app
from app.models import AuditEvent, AuditAction
from tests.conftest import auth_headers


def test_no_mutation_routes_exist_for_audit_events():
    for route in app.routes:
        path = getattr(route, "path", "")
        if "audit" in path:
            methods = getattr(route, "methods", set()) or set()
            assert "PUT" not in methods and "DELETE" not in methods and "PATCH" not in methods


def test_investigation_creation_emits_audit_event(client, user, db_session):
    resp = client.post("/api/v1/investigations", json={"title": "Test"}, headers=auth_headers(user))
    inv_id = resp.json()["id"]

    events = db_session.query(AuditEvent).filter(
        AuditEvent.investigation_id == inv_id,
        AuditEvent.action == AuditAction.INVESTIGATION_CREATED,
    ).all()
    assert len(events) == 1


def test_status_change_emits_audit_event(client, user, db_session):
    headers = auth_headers(user)
    inv = client.post("/api/v1/investigations", json={"title": "Test"}, headers=headers).json()
    client.post(f"/api/v1/investigations/{inv['id']}/status", json={"status": "UNDER_REVIEW"}, headers=headers)

    events = db_session.query(AuditEvent).filter(
        AuditEvent.investigation_id == inv["id"],
        AuditEvent.action == AuditAction.INVESTIGATION_STATUS_CHANGED,
    ).all()
    assert len(events) == 1
    assert events[0].metadata_json == {"from": "AWAITING_ANALYSIS", "to": "UNDER_REVIEW"}
