import secrets
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.session import SESSION_COOKIE, issue_session, session_valid


@pytest.fixture
def access_key():
    return secrets.token_urlsafe(32)


@pytest.fixture
def client(monkeypatch, access_key):
    monkeypatch.setenv("QR_SHIELD_API_KEY", access_key)
    return TestClient(app)


def _analyze(client, **kwargs):
    return client.post("/api/analyze/text", json={"payload": "https://example.com"}, **kwargs)


def test_status_reports_sign_in_required(client):
    assert client.get("/api/session").json() == {"auth_required": True, "authenticated": False}


def test_status_without_api_key_needs_no_sign_in(monkeypatch):
    monkeypatch.delenv("QR_SHIELD_API_KEY", raising=False)
    assert TestClient(app).get("/api/session").json() == {"auth_required": False, "authenticated": True}


def test_api_rejects_requests_without_key_or_session(client):
    assert _analyze(client).status_code == 401


def test_header_key_still_works(client, access_key):
    assert _analyze(client, headers={"X-API-Key": access_key}).status_code == 200


def test_sign_in_sets_cookie_that_authorizes_the_api(client, access_key):
    response = client.post("/api/session", json={"key": access_key})
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Path=/api" in cookie
    assert access_key not in cookie
    assert client.get("/api/session").json()["authenticated"] is True
    assert _analyze(client).status_code == 200


def test_wrong_key_is_rejected_without_cookie(client):
    response = client.post("/api/session", json={"key": "wrong"})
    assert response.status_code == 401
    assert "set-cookie" not in response.headers
    assert _analyze(client).status_code == 401


def test_sign_out_clears_the_session(client, access_key):
    client.post("/api/session", json={"key": access_key})
    client.delete("/api/session")
    assert _analyze(client).status_code == 401


def test_forged_or_expired_sessions_are_rejected(client, access_key):
    token = issue_session(access_key, time.time())
    expiry, nonce, signature = token.split(".")
    for forged in (f"{int(expiry) + 999}.{nonce}.{signature}", f"{expiry}.{nonce}.{'0' * 64}", "garbage", "1.x.y"):
        client.cookies.set(SESSION_COOKIE, forged, path="/api")
        assert _analyze(client).status_code == 401
    assert not session_valid(issue_session(access_key, time.time() - 9 * 3600), access_key, time.time())
    assert not session_valid("1.é.x", access_key, time.time())


def test_rotating_the_api_key_ends_sessions(client, access_key, monkeypatch):
    client.post("/api/session", json={"key": access_key})
    monkeypatch.setenv("QR_SHIELD_API_KEY", access_key + "-rotated")
    assert _analyze(client).status_code == 401


def test_non_ascii_api_key_header_is_rejected_not_a_server_error(client):
    response = _analyze(client, headers={"X-API-Key": "clé".encode()})
    assert response.status_code == 401


def test_cross_site_sign_in_is_rejected(client, access_key):
    response = client.post("/api/session", json={"key": access_key}, headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 403
