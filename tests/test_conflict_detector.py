from agentwall.layer1.conflict_detector import ConflictDetector


def test_block_and_audit_overlap_is_not_contradiction():
    rules = [
        {"name": "block sensitive domain", "tool": "http_get", "match": {"url": {"contains": "evil.com"}}, "action": "BLOCK"},
        {"name": "audit external get", "tool": "http_get", "match": {"url": {"regex": "^https?://"}}, "action": "AUDIT"},
    ]
    issues = ConflictDetector().check(rules)
    assert not any(i["type"] == "contradiction" for i in issues)


def test_block_and_permit_overlap_is_contradiction():
    rules = [
        {"name": "block all bash", "tool": "bash", "action": "BLOCK"},
        {"name": "permit all bash", "tool": "bash", "action": "PERMIT"},
    ]
    issues = ConflictDetector().check(rules)
    assert any(i["type"] == "contradiction" for i in issues)


def test_specific_tool_rule_does_not_shadow_wildcard_tool_rule():
    rules = [
        {"name": "block any bash", "tool": "bash", "action": "BLOCK"},
        {"name": "block tunnel domains", "tool": "*", "match": {"url": {"contains": "ngrok.io"}}, "action": "BLOCK"},
    ]
    issues = ConflictDetector().check(rules)
    assert not any(i["type"] == "shadow" for i in issues)
