from tests.conftest import auth_headers


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_login_success(client, user):
    resp = client.post("/api/v1/auth/login", data={"username": user.email, "password": "password123"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password(client, user):
    resp = client.post("/api/v1/auth/login", data={"username": user.email, "password": "wrong"})
    assert resp.status_code == 401


def test_unauthenticated_request_rejected(client):
    resp = client.get("/api/v1/investigations")
    assert resp.status_code == 401
