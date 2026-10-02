import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
import sqlalchemy as org_sa
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

# NOTE ON TEST DATABASE: the test suite runs against SQLite for speed and
# zero-external-dependency portability. Production deployments run
# against PostgreSQL via the Alembic migrations in alembic/versions/.
# No model uses a Postgres-only column type, and the one Postgres-only
# behavior (the append-only trigger on audit_events) is guarded by a
# dialect check in the migration itself and is exercised only when
# actually running against Postgres -- see IMPLEMENTATION_NOTES.md.
TEST_DB_URL = "sqlite:///:memory:"

os.environ.setdefault('DATABASE_URL', TEST_DB_URL)
os.environ.setdefault('HOPZERO_LLM_PROVIDER', 'offline_deterministic_fallback')

# The test suite runs with a known internal-service key configured so
# tests can exercise the trusted deterministic-producer path. This is
# a test-only value, set via environment variable exactly the way a
# real deployment would (see app/config.py -- there is still no
# hardcoded fallback in source). A dedicated test in
# test_internal_service_key.py separately verifies behavior when this
# variable is absent.
TEST_INTERNAL_SERVICE_KEY = "test-only-internal-service-key-do-not-use-in-production"
os.environ["HOPZERO_INTERNAL_SERVICE_KEY"] = TEST_INTERNAL_SERVICE_KEY

TEST_N8N_INGEST_KEY = "test-only-n8n-ingest-key-do-not-use-in-production"
os.environ["HOPZERO_N8N_INGEST_KEY"] = TEST_N8N_INGEST_KEY

from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Organization, User, UserRole  # noqa: E402
from app.security import hash_password, create_access_token, INTERNAL_SERVICE_KEY_HEADER  # noqa: E402

engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)



def internal_service_headers(u=None) -> dict:
    """
    Combined headers for the trusted deterministic-producer path: a
    normal user JWT (for org scoping/audit attribution) plus the
    X-Internal-Service-Key header (the actual producer credential).
    """
    headers = {INTERNAL_SERVICE_KEY_HEADER: TEST_INTERNAL_SERVICE_KEY}
    if u is not None:
        headers.update(auth_headers(u))
    return headers


@pytest.fixture()
def db_session():
    import app.models
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db_session):
    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def org(db_session):
    o = Organization(name="Acme Security")
    db_session.add(o)
    db_session.commit()
    db_session.refresh(o)
    return o


@pytest.fixture()
def other_org(db_session):
    o = Organization(name="Other Corp")
    db_session.add(o)
    db_session.commit()
    db_session.refresh(o)
    return o


def _make_user(db_session, org, email, role=UserRole.ANALYST):
    u = User(
        organization_id=org.id,
        email=email,
        hashed_password=hash_password("password123"),
        role=role,
    )
    db_session.add(u)
    db_session.commit()
    db_session.refresh(u)
    return u


@pytest.fixture()
def user(db_session, org):
    return _make_user(db_session, org, "analyst@acme.test")


@pytest.fixture()
def other_org_user(db_session, other_org):
    return _make_user(db_session, other_org, "analyst@other.test")


def auth_headers(u) -> dict:
    token = create_access_token(user_id=u.id, organization_id=u.organization_id, role=u.role.value)
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------ AI helpers --

def create_investigation(client, u, title="Test investigation"):
    return client.post("/api/v1/investigations", json={"title": title}, headers=auth_headers(u)).json()


def create_run(client, u, inv_id):
    from app.database import get_db
    db_gen = client.app.dependency_overrides[get_db]()
    db = next(db_gen)
    from app.models import AnalysisRun, AnalysisRunStatus
    from uuid import uuid4
    from app.models import Artifact
    artifact = Artifact(id=str(uuid4()), investigation_id=inv_id, original_filename='dummy.eml', storage_path='/dev/null', mime_type='message/rfc822', size_bytes=100, original_artifact_sha256='dummy')
    db.add(artifact)
    db.commit()
    db.refresh(u)
    run = AnalysisRun(id=str(uuid4()), investigation_id=inv_id, artifact_id=artifact.id, status=AnalysisRunStatus.QUEUED)
    db.add(run)
    db.commit()
    db.refresh(u)
    db.refresh(run)
    run_id = run.id
    return {'id': run_id, 'investigation_id': inv_id, 'status': 'QUEUED'}


def create_source_fact(client, u, inv_id, run_id, text):
    body = {
        "analysis_run_id": run_id,
        "fact_type": "raw_source_text",
        "payload": {"text": text},
        "produced_by": "forensics_parser_v1",
    }
    return client.post(f"/api/v1/investigations/{inv_id}/facts", json=body, headers=auth_headers(u)).json()


def create_ai_execution(client, u, inv_id, run_id, **overrides):
    body = {
        "model_identifier": "test-model",
        "model_version_or_digest": "sha256:deadbeef",
        "prompt_schema_version": "prompt-v1",
        "deterministic_context_snapshot_hash": "sha256:contextcontextcontext",
        "ai_generation_parameters": {"temperature": 0.0, "seed": 42},
    }
    body.update(overrides)
    return client.post(
        f"/api/v1/investigations/{inv_id}/analysis-runs/{run_id}/ai-execution",
        json=body, headers=auth_headers(u),
    ).json()


def submit_ai_candidate(client, u, inv_id, run_id, **overrides):
    body = {
        "qualification_code": "FINANCIAL_REQUEST",
        "claim_signature": "payment_transfer_request",
        "supporting_text": "requests to transfer funds",
        "source_fact_id": "",
        "model_suggested_strength": "Strong",
        "model_confidence": "high",
        "produced_by": "ai_reasoner",
    }
    body.update(overrides)
    return client.post(
        f"/api/v1/investigations/{inv_id}/analysis-runs/{run_id}/ai-candidates",
        json=body, headers=auth_headers(u),
    )















