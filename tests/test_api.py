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
