class RBACChecker:
    """
    Role-Based Access Control for AI Agents.
    Ensures that an agent is authorized to use a specific tool based on its assigned roles.
    """
    def __init__(self):
        self.reload()

    def reload(self):
        # In a real system, this might load from a DB or YAML.
        # For now, we refresh the hardcoded bindings (updated to include simulation agents).
        self.role_bindings = {
            "agent_finance":  ["read_balance", "generate_invoice"],
            "agent_devops":   ["read_logs", "restart_server"],
            "agent_admin":    ["*"],
            "red-team-agent": ["*"],
            "benign-agent":   ["read_file", "write_file", "sql_query", "send_email"]
        }
        print("[RBAC] Permissions reloaded.")

    def check(self, call: dict) -> dict:
        agent_id = call.get("agent_id", "unknown")
        tool_name = call.get("tool_name", "")

        allowed_tools = self.role_bindings.get(agent_id, [])
        
        if "*" in allowed_tools or tool_name in allowed_tools:
            return {"action": "PERMIT", "reason": "Authorized by RBAC"}
            
        return {
            "action": "BLOCK", 
            "reason": f"RBAC Denied: Agent '{agent_id}' is not authorized to use tool '{tool_name}'"
        }
