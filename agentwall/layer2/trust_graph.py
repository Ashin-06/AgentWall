import os
from collections import defaultdict


# Critical Execution Tools (require Level 2 / Admin)
EXEC_TOOLS = {"bash", "python_repl", "sql_query"}

# Standard High Privilege Tools (require Level 1)
HIGH_PRIV_TOOLS = {
    "send_email", "write_file", "http_post", "read_file",
}

_TRUST_LEVELS = {
    "admin": 2, "orchestrator": 2,
    "finance_bot": 1, "research_bot": 1, "code_bot": 1,
    "unknown": 0,
}


class TrustGraph:
    _instance = None

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls):
        cls._instance = None

    def __init__(self):
        # Redis implementation for horizontal scaling
        self.redis_url = os.getenv("REDIS_URL", "redis-cluster.agentwall.svc.cluster.local:6379")
        if self.redis_url:
            try:
                import redis
                self._r = redis.from_url(self.redis_url, decode_responses=True, socket_connect_timeout=1)
                self._r.ping() # Verify connection
                print(f"[TrustGraph] [DISTRIBUTED] State sync active via Redis: {self.redis_url}")
            except Exception as e:
                print(f"[TrustGraph] [FALLBACK] Redis connection failed ({e}). Using local state.")
                self.redis_url = None
                self._chains = defaultdict(list)
        else:
            self._chains = defaultdict(list)
            # Only warn if in production mode
            if os.getenv("AGENTWALL_ENV") == "production":
                print("[TrustGraph] [CRITICAL] Running in PRODUCTION without Redis. Scaling is DISABLED.")

    def record_delegation(self, session_id: str, caller: str, callee: str):
        """Record that caller delegated to callee in this session."""
        if self.redis_url:
            self._r.sadd(f"chain:{session_id}", caller, callee)
            self._r.expire(f"chain:{session_id}", 3600)  # 1-hour TTL
        else:
            chain = self._chains[session_id]
            for agent in (caller, callee):
                if agent and agent not in chain:
                    chain.append(agent)

    def _get_chain(self, session_id: str, default_agent: str) -> list[str]:
        if self.redis_url:
            members = list(self._r.smembers(f"chain:{session_id}"))
            return members if members else [default_agent]
        return self._chains.get(session_id, [default_agent])

    def check_delegation(self, call: dict) -> dict:
        session_id = call.get("session_id", "default")
        agent_id   = call.get("agent_id", "unknown")
        tool_name  = call.get("tool_name", "")
        
        chain = self._get_chain(session_id, agent_id)
        if agent_id not in chain:
            if self.redis_url: self._r.sadd(f"chain:{session_id}", agent_id)
            else: self._chains[session_id].append(agent_id)
            chain.append(agent_id)

        # Find minimum trust in chain (weakest link principle)
        # P1 Fix: Default trust level is now 1 for unlisted agents to avoid FPs on benign file reads
        # Only explicitly 'unknown' agents or those failing RBAC get 0.
        min_trust = min(_TRUST_LEVELS.get(a, 1) for a in chain)

        # 1. Check for Shell/Code Execution (Requires Level 2)
        if tool_name in EXEC_TOOLS and min_trust < 2:
            return {
                "action": "BLOCK",
                "reason": f"Privilege Escalation Blocked: Execution tool '{tool_name}' requires Admin trust (level=2), but chain {chain} has min_trust={min_trust}.",
                "chain":  chain,
            }

        # 2. Check for Standard High Priv Tools (Requires Level 1)
        if tool_name in HIGH_PRIV_TOOLS and min_trust < 1:
            return {
                "action": "BLOCK",
                "reason": f"Confused Deputy: delegation chain {chain} has "
                          f"insufficient trust (level={min_trust}) for '{tool_name}'",
                "chain":  chain,
            }
            
        return {"action": "PERMIT", "chain": chain, "min_trust": min_trust}
