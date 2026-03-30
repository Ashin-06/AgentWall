"""
Role-Based Access Control for AI agents.

Treat agents like employees:
  - Each agent_id has a "role"
  - Each role has an allowlist of tools it may call
  - Calling a tool outside the role = instant BLOCK

Configure in policy.yaml under `rbac:` section.

Example:
  rbac:
    finance_bot:
      allowed_tools: [sql_query, read_file, send_email]
      allowed_paths: ["/workspace/finance/*"]
    research_bot:
      allowed_tools: [http_get, read_file, write_file, memory_write]
    default:
      allowed_tools: [read_file, write_file, memory_read]
      deny_all_others: true
"""
import os
from pathlib import Path
import yaml


DEFAULT_POLICY = Path(__file__).parent.parent / "config" / "policy.yaml"


class RBACEngine:
    def __init__(self, policy_path: str = None):
        path = policy_path or os.getenv("AGENTWALL_POLICY", str(DEFAULT_POLICY))
        self._roles = self._load(path)

    def _load(self, path: str) -> dict:
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return data.get("rbac", {})
        except FileNotFoundError:
            return {}

    def reload(self):
        self.__init__()

    def check(self, call: dict) -> dict:
        """
        Returns {"allowed": bool, "reason": str}
        """
        agent_id  = call.get("agent_id", "unknown")
        tool_name = call.get("tool_name", "")

        # Find role for agent (exact match, then prefix match, then default)
        role_config = (
            self._roles.get(agent_id) or
            self._roles.get(self._find_role_prefix(agent_id)) or
            self._roles.get("default")
        )

        if not role_config:
            return {"allowed": True, "reason": "no_rbac_config"}

        allowed_tools = role_config.get("allowed_tools", [])
        deny_others   = role_config.get("deny_all_others", False)

        if allowed_tools and tool_name not in allowed_tools:
            if deny_others or role_config.get("strict", False):
                return {
                    "allowed": False,
                    "reason":  f"RBAC: agent '{agent_id}' role does not permit tool '{tool_name}'. "
                               f"Allowed: {allowed_tools}",
                }

        # Check path restrictions if applicable
        if "allowed_paths" in role_config:
            import fnmatch
            path_arg = (call.get("arguments", {}).get("path", "") or
                        call.get("arguments", {}).get("file", ""))
            if path_arg:
                allowed = any(
                    fnmatch.fnmatch(path_arg, pattern)
                    for pattern in role_config["allowed_paths"]
                )
                if not allowed:
                    return {
                        "allowed": False,
                        "reason":  f"RBAC: path '{path_arg}' not in allowed paths for '{agent_id}'",
                    }

        return {"allowed": True, "reason": "rbac_pass"}

    def _find_role_prefix(self, agent_id: str) -> str | None:
        """Match agent_id against role prefixes (e.g., 'finance_*' matches 'finance_bot_1')."""
        import fnmatch
        for role_name in self._roles:
            if "*" in role_name and fnmatch.fnmatch(agent_id, role_name):
                return role_name
        return None
