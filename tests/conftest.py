import pytest
import os
from fastapi.testclient import TestClient

# Force in-memory DB and test environment variables before anything is imported
os.environ["AGENTWALL_DB"] = ":memory:"
os.environ["AGENTWALL_ADMIN_PASSWORD"] = "test_admin"
os.environ["AGENTWALL_AUTH_ENABLED"] = "0"

from agentwall.main import app
from agentwall.audit.schema import init_db

@pytest.fixture(scope="session", autouse=True)
def setup_db():
    """Ensure the database schema is initialized before any tests run."""
    init_db()
    yield

@pytest.fixture
def client():
    """Provides a TestClient for testing FastAPI endpoints."""
    with TestClient(app) as client:
        yield client
