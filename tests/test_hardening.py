"""Metrics auth, constant-time API keys, login-attempt eviction, WebSocket auth, read-only static root."""
import json
import time

import pytest
from starlette.websockets import WebSocketDisconnect

import agentwall.main as main

KEY = "hardening-test-key-0123456789abcdef01234"


@pytest.fixture
def auth_on(monkeypatch):
    monkeypatch.setattr("agentwall.auth.AUTH_ENABLED", True)
    monkeypatch.setattr("agentwall.auth.API_KEYS", {KEY})


def test_metrics_requires_auth(client, auth_on):
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": f"Bearer {KEY}"}).status_code == 200
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_api_key_check(auth_on):
    from agentwall.auth import valid_api_key
    assert valid_api_key(KEY) and not valid_api_key(KEY[:-1]) and not valid_api_key("")


def test_stale_login_attempts_are_evicted(client):
    main.login_attempts.clear()
    main.login_attempts["10.0.0.9"] = [time.time() - 120]
    client.post("/auth/login", json={"password": "wrong"})
    assert "10.0.0.9" not in main.login_attempts
    assert len(main.login_attempts) == 1  # the test client's own failure


def test_websocket_accepts_without_auth_when_disabled(client):
    with client.websocket_connect("/ws/intercept"):
        _wait_for(lambda: main.active_connections)
    _wait_for(lambda: not main.active_connections)


def test_websocket_auth_message(client, auth_on):
    with client.websocket_connect("/ws/intercept") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": KEY}))
        _wait_for(lambda: main.active_connections)
    with client.websocket_connect("/ws/intercept") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": "not-valid"}))
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()


def test_root_without_dashboard_build_writes_nothing(client, tmp_path, monkeypatch):
    monkeypatch.setattr(main, "final_static_path", str(tmp_path))
    r = client.get("/")
    assert r.status_code == 200 and "Dashboard build not found" in r.text
    assert list(tmp_path.iterdir()) == []


def _wait_for(cond, timeout=2.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return
        time.sleep(0.02)
    raise AssertionError("condition not met")
