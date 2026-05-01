"""
CrewAI adapter — patches BaseTool.run() at the class level.

Usage:
  from adapters.crewai_adapter import patch_crewai
  patch_crewai(session_id="s1", agent_id="my-crew")
  # Then use CrewAI as normal — all tool calls are intercepted

Or per-agent:
  from adapters.crewai_adapter import AgentWallCrewMixin
  class MyAgent(AgentWallCrewMixin, Agent): ...
"""
import uuid
import os
import httpx

# Configuration
AGENTWALL = os.getenv("AGENTWALL_URL", "http://localhost:8000")


def patch_crewai(session_id: str = None, agent_id: str = "crewai-agent"):
    """Monkey-patch CrewAI BaseTool to intercept all tool calls."""
    try:
        from crewai_tools import BaseTool
    except ImportError:
        print("[AgentWall] crewai_tools not installed — skipping patch")
        return

    sid = session_id or str(uuid.uuid4())
    original_run = BaseTool.run

    def guarded_run(self, *args, **kwargs):
        payload = {
            "action":       self.name,
            "action_input": args[0] if args else kwargs,
            "session_id":   sid,
            "agent_id":     agent_id,
        }
        try:
            r      = httpx.post(f"{AGENTWALL}/intercept", json=payload, timeout=5.0)
            result = r.json()
            if result["verdict"] == "BLOCK":
                raise PermissionError(f"AgentWall blocked {self.name}: {result['reason']}")
        except httpx.RequestError:
            pass  # fail open — firewall unreachable

        output = original_run(self, *args, **kwargs)

        # Sanitise output
        try:
            r2 = httpx.post(f"{AGENTWALL}/intercept/output", json={
                "tool_name": self.name, "output": str(output),
                "session_id": sid, "agent_id": agent_id,
            }, timeout=5.0)
            return r2.json().get("output", output)
        except:
            return output

    BaseTool.run = guarded_run
    print(f"[AgentWall] CrewAI BaseTool patched (session={sid})")
