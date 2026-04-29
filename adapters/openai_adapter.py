"""
Drop-in GuardedOpenAI for OpenAI SDK.
Intercepts tool calls AND sanitises outputs bidirectionally.

Usage:
  from adapters.openai_adapter import GuardedOpenAI
  client = GuardedOpenAI()
  response = client.chat_completions_create(model="gpt-4o", messages=[...], tools=[...])
"""
import uuid
import json
import os
import httpx
from openai import OpenAI

# Configuration
AGENTWALL = os.getenv("AGENTWALL_URL", "http://localhost:8000")


class GuardedOpenAI:
    def __init__(self, agent_id: str = "openai-agent"):
        self._client     = OpenAI()
        self._agent_id   = agent_id
        self._session_id = str(uuid.uuid4())

    def chat_completions_create(self, **kwargs):
        response = self._client.chat.completions.create(**kwargs)
        choice   = response.choices[0]
        msg      = choice.message

        if msg.tool_calls:
            for tc in msg.tool_calls:
                verdict = self._intercept(tc)
                if verdict["verdict"] == "BLOCK":
                    raise PermissionError(
                        f"🛡️ AgentWall BLOCKED tool '{tc.function.name}': "
                        f"{verdict['reason']} [{verdict.get('mitre_id','')}]"
                    )
                if verdict["verdict"] == "AUDIT":
                    print(f"[AgentWall ⚠️] {tc.function.name}: {verdict['reason']}")

        return response

    def sanitise_output(self, tool_name: str, output: str) -> str:
        r = httpx.post(f"{AGENTWALL}/intercept/output", json={
            "tool_name":  tool_name,
            "output":     output,
            "session_id": self._session_id,
            "agent_id":   self._agent_id,
        }, timeout=5.0)
        data = r.json()
        if data.get("sanitised"):
            print(f"[AgentWall 🧹] Sanitised {len(data['removals'])} patterns from {tool_name} output")
        return data["output"]

    def _intercept(self, tc) -> dict:
        try:    args = json.loads(tc.function.arguments)
        except: args = {"raw": tc.function.arguments}
        r = httpx.post(f"{AGENTWALL}/intercept", json={
            "type":       "function",
            "id":         tc.id,
            "function":   {"name": tc.function.name, "arguments": args},
            "session_id": self._session_id,
            "agent_id":   self._agent_id,
        }, timeout=5.0)
        return r.json()
