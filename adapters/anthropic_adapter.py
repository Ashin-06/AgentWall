"""
Drop-in GuardedClient for Anthropic SDK.
Intercepts tool calls AND sanitises tool outputs bidirectionally.
"""
import uuid
import os
import httpx
import anthropic

# Configuration
AGENTWALL = os.getenv("AGENTWALL_URL", "http://localhost:8000")


class GuardedClient:
    def __init__(self, agent_id: str = "my-agent"):
        self._client     = anthropic.Anthropic()
        self._agent_id   = agent_id
        self._session_id = str(uuid.uuid4())

    def messages_create(self, **kwargs):
        response = self._client.messages.create(**kwargs)
        for block in response.content:
            if block.type == "tool_use":
                # Intercept the call
                verdict = self._intercept_call(block, kwargs.get("system",""))
                if verdict["verdict"] == "BLOCK":
                    raise PermissionError(
                        f"🛡️ AgentWall BLOCKED: {verdict['reason']} "
                        f"[{verdict.get('mitre_id','')}] "
                        f"(event={verdict['event_id']})"
                    )
                if verdict["verdict"] == "AUDIT":
                    print(f"[AgentWall ⚠️  AUDIT] {block.name}: {verdict['reason']}")
        return response

    def sanitise_tool_output(self, tool_name: str, output: str) -> str:
        """Call this after executing a tool, before returning result to agent."""
        r = httpx.post(f"{AGENTWALL}/intercept/output", json={
            "tool_name":  tool_name,
            "output":     output,
            "session_id": self._session_id,
            "agent_id":   self._agent_id,
        }, timeout=5.0)
        data = r.json()
        if data.get("sanitised"):
            print(f"[AgentWall 🧹 SANITISED] Removed {len(data['removals'])} patterns "
                  f"from {tool_name} output")
        return data["output"]

    def _intercept_call(self, block, context) -> dict:
        r = httpx.post(f"{AGENTWALL}/intercept", json={
            "type":       "tool_use",
            "id":         block.id,
            "name":       block.name,
            "input":      block.input,
            "session_id": self._session_id,
            "agent_id":   self._agent_id,
            "context":    context[:800] if context else None,
        }, timeout=5.0)
        return r.json()
