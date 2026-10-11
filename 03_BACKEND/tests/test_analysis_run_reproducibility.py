"""
Tests for HZ8: Reproducibility fields in AnalysisRunConfig.
===========================================================

Validates that:
1. AnalysisRunConfig records:
   - llm.model
   - llm.digest
   - llm.quantization
   - llm.num_ctx
   - llm.options_hash
   - llm.prompt_version
   - llm.schema_version
2. Hashing is canonical and deterministic.
3. AnalysisRun persists config JSON in database.
4. Full execution pipeline populates reproducibility envelope.
5. Tool endpoint GET /api/v1/tool/investigations/{id}/reproducibility exposes the envelope.
"""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    AnalysisRun,
    Artifact,
    Investigation,
    InvestigationStatus,
    Organization,
    User,
    UserRole,
)
from app.services.analysis_run_service import create_analysis_run
from app.services.ai_reasoner_service import resolve_llm_reproducibility
from tests.conftest import auth_headers
from hopzero.core.models import AnalysisRunConfig


# ---------------------------------------------------------------------------
# 1. Config Object & Hashing Tests
# ---------------------------------------------------------------------------

def test_analysis_run_config_hash_and_serialization():
    cfg1 = AnalysisRunConfig(
        llm_model="hermes3:3b",
        llm_digest="sha256:testdigest123",
        llm_quantization="Q4_K_M",
        llm_num_ctx=4096,
        llm_prompt_version="prompt-v1",
        llm_schema_version="proposal-v1",
    )

    d1 = cfg1.to_dict()
    assert d1["llm"]["model"] == "hermes3:3b"
    assert d1["llm"]["digest"] == "sha256:testdigest123"
    assert d1["llm"]["quantization"] == "Q4_K_M"
    assert d1["llm"]["num_ctx"] == 4096
    assert d1["llm"]["options_hash"] is not None
    assert d1["reproducibility_fingerprint"] is not None

    # Round-trip reconstruction
    cfg2 = AnalysisRunConfig.from_dict(d1)
    assert cfg2.llm_model == cfg1.llm_model
    assert cfg2.llm_digest == cfg1.llm_digest
    assert cfg2.llm_quantization == cfg1.llm_quantization
    assert cfg2.llm_num_ctx == cfg1.llm_num_ctx
    assert cfg2.options_hash == cfg1.options_hash
    assert cfg2.compute_reproducibility_fingerprint() == cfg1.compute_reproducibility_fingerprint()

    # Altering a parameter alters the options hash and fingerprint
    cfg_altered = AnalysisRunConfig(
        llm_model="hermes3:3b",
        llm_digest="sha256:testdigest123",
        llm_quantization="Q8_0",  # changed
        llm_num_ctx=4096,
    )
    assert cfg_altered.options_hash != cfg1.options_hash
    assert cfg_altered.compute_reproducibility_fingerprint() != cfg1.compute_reproducibility_fingerprint()


def test_resolve_llm_reproducibility():
    repro = resolve_llm_reproducibility()
    assert "model" in repro
    assert "digest" in repro
    assert "quantization" in repro
    assert "num_ctx" in repro
    assert "options_hash" in repro
    assert "prompt_version" in repro
    assert "schema_version" in repro
    assert repro["num_ctx"] > 0
    assert len(repro["options_hash"]) == 64  # SHA-256


# ---------------------------------------------------------------------------
# 2. Database Persistence & Pipeline Integration Tests
# ---------------------------------------------------------------------------

def test_analysis_run_persists_config_in_database(db_session):
    org = Organization(name="Org Repro")
    db_session.add(org)
    db_session.flush()

    user = User(
        organization_id=org.id,
        email="repro@hopzero.local",
        hashed_password="pw",
        role=UserRole.ANALYST,
    )
    db_session.add(user)
    db_session.flush()

    inv = Investigation(
        organization_id=org.id,
        title="Repro Investigation",
        created_by_user_id=user.id,
    )
    db_session.add(inv)
    db_session.flush()

    custom_cfg = AnalysisRunConfig(
        llm_model="custom-hermes",
        llm_digest="sha256:abc456",
        llm_quantization="Q4_0",
        llm_num_ctx=2048,
    )

    run = create_analysis_run(
        db_session,
        user=user,
        investigation_id=inv.id,
        artifact_id="art-test-repro",
        config=custom_cfg,
    )

    assert run.config is not None
    assert run.config["llm"]["model"] == "custom-hermes"
    assert run.config["llm"]["digest"] == "sha256:abc456"
    assert run.config["llm"]["quantization"] == "Q4_0"
    assert run.config["llm"]["num_ctx"] == 2048
    assert "reproducibility_fingerprint" in run.config


# ---------------------------------------------------------------------------
# 3. Tool API Inspection Endpoint Test
# ---------------------------------------------------------------------------

def test_tool_inspect_reproducibility_endpoint(client, db_session):
    org = Organization(name="Tool Repro Org")
    db_session.add(org)
    db_session.flush()

    user = User(
        organization_id=org.id,
        email="tool_repro@hopzero.local",
        hashed_password="pw",
        role=UserRole.ADMIN,
    )
    db_session.add(user)
    db_session.flush()

    inv = Investigation(
        organization_id=org.id,
        title="Tool Repro Inv",
        created_by_user_id=user.id,
    )
    db_session.add(inv)
    db_session.flush()

    cfg = AnalysisRunConfig(
        llm_model="hermes3:3b",
        llm_digest="sha256:digest-audit",
        llm_quantization="Q4_K_M",
    )
    run = create_analysis_run(db_session, user=user, investigation_id=inv.id, artifact_id="art-1", config=cfg)
    inv.current_analysis_run_id = run.id
    db_session.commit()

    resp = client.get(
        f"/api/v1/tool/investigations/{inv.id}/reproducibility",
        headers=auth_headers(user),
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["investigation_id"] == inv.id
    assert data["run_id"] == run.id
    repro = data["reproducibility"]
    assert repro["llm"]["model"] == "hermes3:3b"
    assert repro["llm"]["digest"] == "sha256:digest-audit"
    assert repro["llm"]["quantization"] == "Q4_K_M"
    assert "options_hash" in repro["llm"]
    assert "reproducibility_fingerprint" in repro
