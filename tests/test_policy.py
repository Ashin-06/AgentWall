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
    assert result["action"] == "PERMIT"

def test_policy_block_malicious_path(policy_engine):
    """Test that a malicious file path triggers a BLOCK verdict."""
    call = {
        "session_id": "test_sess",
        "agent_id": "test_agent",
        "tool_name": "read_file",
        "arguments": {"path": "/etc/passwd"}
    }
    result = policy_engine.check(call)
    assert result["action"] == "BLOCK"
    assert result["rule"] == "block pii and user_data file reads"

def test_policy_block_system_command(policy_engine):
    """Test that restricted system commands trigger a BLOCK verdict."""
    call = {
        "session_id": "test_sess",
        "agent_id": "test_agent",
        "tool_name": "bash",
        "arguments": {"command": "rm -rf /"}
    }
    result = policy_engine.check(call)
    assert result["action"] == "BLOCK"
    assert result["rule"] == "block destructive rm"


@pytest.mark.parametrize("tool_name", ["bash", "Bash", "BASH"])
def test_policy_rule_names_are_case_insensitive(policy_engine, tool_name):
    """A differently cased tool name must not slip past a rule."""
    call = {"session_id": "s", "agent_id": "a", "tool_name": tool_name, "arguments": {"command": "rm -rf /"}}
    assert policy_engine.check(call)["action"] == "BLOCK"


def test_conflict_detector_reports_only_unreachable_rules():
    from agentwall.layer1.conflict_detector import ConflictDetector
    narrow_block = {"name": "block metadata", "tool": "*", "match": {"url": {"contains": ["169.254"]}}, "action": "BLOCK"}
    broad_audit = {"name": "audit http_get", "tool": "http_get", "action": "AUDIT"}
    block_bash = {"name": "block bash", "tool": "bash", "action": "BLOCK"}
    permit_bash = {"name": "permit bash", "tool": "bash", "action": "PERMIT"}
    issues = ConflictDetector().check([narrow_block, broad_audit, block_bash, permit_bash])
    assert [(i["type"], i["rule_b"]) for i in issues] == [("contradiction", "permit bash")]


def test_shipped_policy_has_no_unreachable_rules():
    import yaml
    from agentwall.layer1.conflict_detector import ConflictDetector
    with open("config/policy.yaml", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert ConflictDetector().check(data["rules"]) == []
