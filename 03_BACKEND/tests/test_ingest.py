import io
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import get_settings
from app.models import Finding
from app.services.score_engine import compute_score
from app.services.floor_engine import evaluate_floors

from tests.conftest import TEST_N8N_INGEST_KEY

settings = get_settings()

VALID_INGEST_KEY = settings.hopzero_n8n_ingest_key or TEST_N8N_INGEST_KEY


class _FakeFinding:
    def __init__(self, id: str, category: str, strength: str, qualification_code: str = ""):
        self.id = id
        self.category = category
        self.strength = strength
        self.qualification_code = qualification_code


def test_ingest_rejects_missing_or_invalid_key(client):
    # Missing key
    resp = client.post(
        "/api/v1/ingest",
        files={"file": ("test.eml", b"From: user@example.com\r\nSubject: Test\r\n\r\nHello", "message/rfc822")},
    )
    assert resp.status_code == 403

    # Invalid key
    resp = client.post(
        "/api/v1/ingest",
        headers={"X-N8N-Ingest-Key": "wrong-secret-key"},
        files={"file": ("test.eml", b"From: user@example.com\r\nSubject: Test\r\n\r\nHello", "message/rfc822")},
    )
    assert resp.status_code == 403


def test_ingest_enforces_25mb_ceiling(client):
    # 26 MB of content exceeds MAX_ARTIFACT_BYTES
    oversized = b"A" * (26 * 1024 * 1024)
    resp = client.post(
        "/api/v1/ingest",
        headers={"X-N8N-Ingest-Key": VALID_INGEST_KEY},
        files={"file": ("huge.eml", oversized, "message/rfc822")},
    )
    assert resp.status_code == 413
    assert "ARTIFACT_TOO_LARGE" in resp.json()["message"]


def test_ingest_valid_email_and_executes_pipeline(client):
    eml_content = (
        b"Received: from mail.attacker.com (mail.attacker.com [198.51.100.25])\r\n"
        b"  by mx.google.com with ESMTP id xyz123\r\n"
        b"  for <target@example.com>; Sun, 13 Sep 2026 12:00:00 +0000\r\n"
        b"From: CEO <ceo@micros0ft.com>\r\n"
        b"To: finance@example.com\r\n"
        b"Subject: Urgent Wire Transfer\r\n"
        b"Message-ID: <wire-req-12345@micros0ft.com>\r\n"
        b"Date: Sun, 13 Sep 2026 12:00:00 +0000\r\n"
        b"\r\n"
        b"Please process urgent transfer to account 987654 immediately: https://bit.ly/fake-wire\r\n"
    )

    resp = client.post(
        "/api/v1/ingest",
        headers={"X-N8N-Ingest-Key": VALID_INGEST_KEY},
        data={
            "ingestion_source": "test_ingestion",
            "provider_message_id": "test-msg-001",
            "title": "Test BEC Email",
            "auto_analyze": "true",
        },
        files={"file": ("sample.eml", eml_content, "message/rfc822")},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["investigation_id"]
    assert data["artifact_id"]
    assert data["analysis_run_id"]
    assert data["status"] == "UNDER_REVIEW"
    assert data["idempotent_replay"] is False

    # Test idempotency: submitting same provider_message_id and same SHA-256 returns 200 duplicate
    resp_replay = client.post(
        "/api/v1/ingest",
        headers={"X-N8N-Ingest-Key": VALID_INGEST_KEY},
        data={
            "ingestion_source": "test_ingestion",
            "provider_message_id": "test-msg-001",
            "title": "Test BEC Email Duplicate",
        },
        files={"file": ("sample.eml", eml_content, "message/rfc822")},
    )
    assert resp_replay.status_code == 200
    replay_data = resp_replay.json()
    assert replay_data["investigation_id"] == data["investigation_id"]
    assert replay_data["artifact_id"] == data["artifact_id"]
    assert replay_data["idempotent_replay"] is True

    # Test conflict: submitting same provider_message_id with DIFFERENT bytes returns 409 INGESTION_ANOMALY
    differing_eml = eml_content + b"\r\nExtra payload altering SHA256"
    resp_conflict = client.post(
        "/api/v1/ingest",
        headers={"X-N8N-Ingest-Key": VALID_INGEST_KEY},
        data={
            "ingestion_source": "test_ingestion",
            "provider_message_id": "test-msg-001",
            "title": "Tampered Duplicate",
        },
        files={"file": ("sample.eml", differing_eml, "message/rfc822")},
    )
    assert resp_conflict.status_code == 409
    assert "INGESTION_ANOMALY" in resp_conflict.json()["message"]

    # Test: different provider ID with same bytes creates a NEW Investigation
    resp_new = client.post(
        "/api/v1/ingest",
        headers={"X-N8N-Ingest-Key": VALID_INGEST_KEY},
        data={
            "ingestion_source": "test_ingestion",
            "provider_message_id": "test-msg-different-provider-id-002",
            "title": "Second Email With Same Bytes",
            "auto_analyze": "false",
        },
        files={"file": ("sample.eml", eml_content, "message/rfc822")},
    )
    assert resp_new.status_code == 201
    new_data = resp_new.json()
    assert new_data["investigation_id"] != data["investigation_id"]
    assert new_data["idempotent_replay"] is False


def test_weak_only_ceiling():
    # In Phase 5, Weak findings use 0.5x multiplier and produce proportional LOW severity scores
    findings = [
        _FakeFinding("f1", "Authentication", "Weak", qualification_code="SPF_FAIL"),
        _FakeFinding("f2", "Domain", "Weak", qualification_code="NEWLY_REGISTERED_DOMAIN"),
        _FakeFinding("f3", "URL", "Weak", qualification_code="LINK_DISPLAY_HREF_MISMATCH"),
        _FakeFinding("f4", "Identity", "Weak", qualification_code="IDENTITY_ANOMALY"),
        _FakeFinding("f5", "Social Engineering", "Weak", qualification_code="FINANCIAL_REQUEST"),
        _FakeFinding("f6", "Attachment", "Weak", qualification_code="SUSPICIOUS_ATTACHMENT"),
    ]
    res = compute_score(findings)
    assert res.total_score == 17  # sum = 28 raw -> round(28/166*100) = 17
    assert res.severity == "LOW"


def test_cf01_floor_triggers():
    # CF-01: PROTECTED_BRAND_LOOKALIKE_DOMAIN + EXPLICIT_BRAND_REPRESENTATION_CLAIM (Moderate+)
    findings = [
        _FakeFinding("f1", "Domain", "Moderate", qualification_code="PROTECTED_BRAND_LOOKALIKE_DOMAIN"),
        _FakeFinding("f2", "Identity", "Moderate", qualification_code="EXPLICIT_BRAND_REPRESENTATION_CLAIM"),
    ]
    floors = evaluate_floors(findings)
    assert "CF-01" in floors

    res = compute_score(findings)
    assert "CF-01" in res.triggered_floor_codes
    assert res.severity == "HIGH"
