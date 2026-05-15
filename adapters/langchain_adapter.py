"""
LangChain v2 callback + tool wrapper.

Two integration modes:
  1. Callback (AgentWallCallback) — attach to any LangChain agent
  2. Wrapped tool (guarded_tool) — wrap individual tools

Usage:
  from adapters.langchain_adapter import AgentWallCallback, guarded_tool

  # Mode 1: callback
  agent = initialize_agent(tools, llm, callbacks=[AgentWallCallback()])

  # Mode 2: wrap specific tools
  safe_bash = guarded_tool(BashTool(), session_id="s1", agent_id="my-agent")
"""
import uuid
import json
import os
import httpx
from langchain.callbacks.base import BaseCallbackHandler
from langchain.tools import BaseTool

# Configuration
AGENTWALL = os.getenv("AGENTWALL_URL", "http://localhost:8000")


class AgentWallCallback(BaseCallbackHandler):
    def __init__(self, session_id: str = None, agent_id: str = "langchain-agent"):
        self.session_id = session_id or str(uuid.uuid4())
        self.agent_id   = agent_id

    def on_tool_start(self, serialized, input_str, **kwargs):
        tool_input = input_str
        if isinstance(tool_input, str):
            try:    tool_input = json.loads(tool_input)
            except: tool_input = {"input": tool_input}

        payload = {
            "tool":       serialized.get("name", "unknown"),
            "tool_input": tool_input,
            "log":        str(kwargs.get("run_id", "")),
            "session_id": self.session_id,
            "agent_id":   self.agent_id,
        }
        try:
            r      = httpx.post(f"{AGENTWALL}/intercept/langchain", json=payload, timeout=5.0)
            result = r.json()
            if result["verdict"] == "BLOCK":
                raise PermissionError(
                    f"🛡️ AgentWall BLOCKED: {result['reason']} "
                    f"[{result.get('mitre_id','')}]"
                )
            if result["verdict"] == "AUDIT":
                print(f"[AgentWall ⚠️] {serialized.get('name')}: {result['reason']}")
        except httpx.RequestError as e:
            print(f"[AgentWall] Firewall unreachable ({e}) — continuing in degraded mode")

    def on_tool_end(self, output: str, **kwargs):
        """Sanitise tool output before it goes back to the agent."""
        try:
            r    = httpx.post(f"{AGENTWALL}/intercept/output", json={
                "output": output, "session_id": self.session_id, "agent_id": self.agent_id,
            }, timeout=5.0)
            data = r.json()
            if data.get("sanitised"):
                print(f"[AgentWall 🧹] Sanitised {len(data['removals'])} patterns from tool output")
            return data["output"]
        except:
            return output


def guarded_tool(tool: BaseTool, session_id: str = None,
                 agent_id: str = "langchain-agent") -> BaseTool:
    """Wrap a LangChain tool with AgentWall interception."""
    original_run = tool._run
    sid = session_id or str(uuid.uuid4())

    def guarded_run(*args, **kwargs):
        # Intercept before
        tool_input = args[0] if args else str(kwargs)
        if isinstance(tool_input, str):
            try:    tool_input_dict = json.loads(tool_input)
            except: tool_input_dict = {"input": tool_input}
        else:
            tool_input_dict = tool_input

        payload = {
            "tool": tool.name, "tool_input": tool_input_dict,
            "session_id": sid, "agent_id": agent_id,
        }
        r      = httpx.post(f"{AGENTWALL}/intercept/langchain", json=payload, timeout=5.0)
        result = r.json()
        if result["verdict"] == "BLOCK":
            raise PermissionError(f"AgentWall blocked {tool.name}: {result['reason']}")

        # Execute
        output = original_run(*args, **kwargs)

        # Sanitise output
        r2   = httpx.post(f"{AGENTWALL}/intercept/output", json={
            "tool_name": tool.name, "output": str(output),
            "session_id": sid, "agent_id": agent_id,
        }, timeout=5.0)
        return r2.json().get("output", output)

    tool._run = guarded_run
    return tool
