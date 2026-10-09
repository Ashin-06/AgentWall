import pytest
import os
from unittest.mock import Mock
from fastapi.testclient import TestClient

# Force in-memory DB and test environment variables before anything is imported
os.environ["AGENTWALL_DB"] = ":memory:"
os.environ["AGENTWALL_ADMIN_PASSWORD"] = "test_admin"
os.environ["AGENTWALL_AUTH_ENABLED"] = "0"
os.environ["AGENTWALL_JWT_SECRET"] = "agentwall-test-secret-not-for-production-123456"
os.environ["DATABASE_URL"] = ""

from agentwall.main import app
from agentwall.audit.schema import init_db

@pytest.fixture(scope="session", autouse=True)
def setup_db():
    """Ensure the database schema is initialized before any tests run."""
    init_db()
    yield

@pytest.fixture
def client(monkeypatch):
    """Provides a TestClient for testing FastAPI endpoints."""
    from agentwall.audit.write_queue import DBWriteQueue
    DBWriteQueue.reset()
    monkeypatch.setattr("agentwall.audit.system_watcher.start_system_watcher", lambda loop: Mock())
    with TestClient(app) as client:
        yield client
    DBWriteQueue.reset()
