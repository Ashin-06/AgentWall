def test_health(client):
    """Test that the application starts and serves the dashboard root."""
    response = client.get("/")
    assert response.status_code == 200
    assert "AgentWall Dashboard" in response.text or "<!DOCTYPE html>" in response.text

def test_login_success(client):
    """Test successful authentication."""
    response = client.post("/auth/login", json={"password": "test_admin"})
    assert response.status_code == 200
    assert "token" in response.json()

def test_login_failure(client):
    """Test failed authentication."""
    response = client.post("/auth/login", json={"password": "wrong_password"})
    assert response.status_code == 401

def test_metrics_endpoint(client):
    """Test that the Prometheus metrics endpoint is accessible."""
    response = client.get("/metrics")
    assert response.status_code == 200


def test_list_limits_are_bound_parameters():
    """get_sessions/get_violations pass LIMIT as a bound parameter and honour it."""
    from agentwall.audit.schema import init_db, write_event, get_sessions, get_violations
    init_db()  # the in-memory DB does not outlive an earlier TestClient
    for i in range(3):
        write_event(session_id=f"limit_{i}", agent_id="a", call_id=f"c{i}", tool_name="bash",
                    arguments={}, verdict="BLOCK", reason="r", details={}, mitre_id=None,
                    latency_ms=1.0)
    assert len(get_sessions(limit=2)) == 2
    assert len(get_violations(limit=1)) == 1
