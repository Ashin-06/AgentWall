"""HITL: high-risk calls are held until an admin approves that exact call, once."""
from unittest.mock import AsyncMock

import pytest

KEY = "hitl-test-agent-key-0123456789abcdef0123"


def _call(args=None):
    return {"session_id": "hitl_s1", "agent_id": "vscode_copilot", "call_id": "c1",
            "tool_name": "drop_table", "arguments": args or {"table": "orders"}}


@pytest.fixture
def hitl_client(client, monkeypatch):
    client.app.state.proxy.proxy.injection.analyse = AsyncMock(return_value={"score": 0.0, "source": "test"})
    return client


def _admin_headers(client):
    token = client.post("/auth/login", json={"password": "test_admin"}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_held_then_approved_once(hitl_client):
    c = hitl_client
    first = c.post("/intercept", json=_call()).json()
    assert first["verdict"] == "BLOCK"
    token = first["details"]["hitl"]["token"]
    assert any(p["token"] == token for p in c.get("/api/hitl/pending").json())

    # Approval is bound to this exact call.
    assert c.post(f"/api/hitl/{token}/approve").json()["status"] == "APPROVED"
    other = c.post("/intercept", json=_call({"table": "users"}), headers={"X-AgentWall-Approval-Token": token}).json()
    assert other["verdict"] == "BLOCK"

    ok = c.post("/intercept", json=_call(), headers={"X-AgentWall-Approval-Token": token}).json()
    assert ok["verdict"] != "BLOCK" and ok["details"]["hitl"]["approved"]
    again = c.post("/intercept", json=_call(), headers={"X-AgentWall-Approval-Token": token}).json()
    assert again["verdict"] == "BLOCK"  # single use


def test_denied_token_does_not_unlock(hitl_client):
    c = hitl_client
    token = c.post("/intercept", json=_call()).json()["details"]["hitl"]["token"]
    assert c.post(f"/api/hitl/{token}/deny").json()["status"] == "DENIED"
    res = c.post("/intercept", json=_call(), headers={"X-AgentWall-Approval-Token": token}).json()
    assert res["verdict"] == "BLOCK"
    assert c.post(f"/api/hitl/{token}/approve").status_code == 404


def test_only_admin_can_decide(hitl_client, monkeypatch):
    c = hitl_client
    monkeypatch.setattr("agentwall.auth.AUTH_ENABLED", True)
    monkeypatch.setattr("agentwall.auth.API_KEYS", {KEY})
    agent = {"X-AgentWall-Key": KEY}
    token = c.post("/intercept", json=_call(), headers=agent).json()["details"]["hitl"]["token"]
    assert c.get("/api/hitl/pending").status_code == 401
    assert c.post(f"/api/hitl/{token}/approve", headers=agent).status_code == 403
    assert c.post(f"/api/hitl/{token}/approve", headers=_admin_headers(c)).status_code == 200
