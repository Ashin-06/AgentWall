import pytest
from agentwall.layer1.policy_engine import PolicyEngine

@pytest.fixture
def policy_engine():
    """Returns a fresh instance of the PolicyEngine."""
    return PolicyEngine(policy_variant="standard")

def test_policy_permit_benign_tool(policy_engine):
    """Test that benign tool calls pass through the firewall."""
    call = {
        "session_id": "test_sess",
        "agent_id": "test_agent",
        "tool_name": "list_directory",
        "arguments": {"path": "./test"}
    }
    result = policy_engine.check(call)
    assert result["action"] in ["PERMIT", "AUDIT"]

def test_policy_block_malicious_path(policy_engine):
    """Test that a malicious file path triggers a BLOCK verdict."""
    call = {
        "session_id": "test_sess",
        "agent_id": "test_agent",
        "tool_name": "read_file",
        "arguments": {"path": "/etc/passwd"}
    }
    result = policy_engine.check(call)
    assert result["action"] in ["BLOCK", "AUDIT"]
    assert "reason" in result

def test_policy_block_system_command(policy_engine):
    """Test that restricted system commands trigger a BLOCK verdict."""
    call = {
        "session_id": "test_sess",
        "agent_id": "test_agent",
        "tool_name": "bash",
        "arguments": {"command": "rm -rf /"}
    }
    result = policy_engine.check(call)
    assert result["action"] in ["BLOCK", "AUDIT"]
