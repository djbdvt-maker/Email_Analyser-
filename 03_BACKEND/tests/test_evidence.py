import hashlib
import io

from app.models import AuditEvent, AuditAction
from tests.conftest import auth_headers


def _create_investigation(client, user):
    resp = client.post("/api/v1/investigations", json={"title": "Test"}, headers=auth_headers(user))
    return resp.json()


def test_artifact_ingestion_computes_sha256(client, user, db_session):
    inv = _create_investigation(client, user)
    content = b"From: alice@example.com\nSubject: Wire transfer\n\nPlease process the transfer."
    expected_sha256 = hashlib.sha256(content).hexdigest()

    files = {"file": ("sample.eml", io.BytesIO(content), "message/rfc822")}
    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/evidence",
        files=files,
        headers=auth_headers(user),
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["original_artifact_sha256"] == expected_sha256
    assert body["size_bytes"] == len(content)
    assert body["export_bundle_sha256"] is None


def test_get_evidence_does_not_emit_export_audit_event(client, user, db_session):
    inv = _create_investigation(client, user)
    content = b"hello world"
    files = {"file": ("sample.eml", io.BytesIO(content), "message/rfc822")}
    upload_resp = client.post(
        f"/api/v1/investigations/{inv['id']}/evidence", files=files, headers=auth_headers(user)
    )
    artifact_id = upload_resp.json()["id"]

    client.get(f"/api/v1/investigations/{inv['id']}/evidence", headers=auth_headers(user))
    client.get(f"/api/v1/investigations/{inv['id']}/evidence/{artifact_id}", headers=auth_headers(user))

    export_events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == AuditAction.EVIDENCE_EXPORTED)
        .all()
    )
    assert export_events == []


def test_export_evidence_emits_exactly_one_audit_event_and_hash(client, user, db_session):
    inv = _create_investigation(client, user)
    content = b"hello world"
    files = {"file": ("sample.eml", io.BytesIO(content), "message/rfc822")}
    upload_resp = client.post(
        f"/api/v1/investigations/{inv['id']}/evidence", files=files, headers=auth_headers(user)
    )
    artifact_id = upload_resp.json()["id"]

    resp = client.post(
        f"/api/v1/investigations/{inv['id']}/evidence/{artifact_id}/export",
        headers=auth_headers(user),
    )
    assert resp.status_code == 200
    export_hash = resp.json()["export_bundle_sha256"]
    assert export_hash is not None
    assert len(export_hash) == 64
    assert export_hash != hashlib.sha256(content).hexdigest()

    export_events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == AuditAction.EVIDENCE_EXPORTED)
        .all()
    )
    assert len(export_events) == 1
