"""
Human-in-the-loop approvals.

A high-risk call that would otherwise be AUDITed is held (BLOCK) with a token. An admin approves or
denies it through /api/hitl. The agent then resends the same call with the header
X-AgentWall-Approval-Token. The token is bound to a fingerprint of that exact call (session, agent,
tool, arguments) and is consumed on use.

Tokens live in Redis when REDIS_URL is set (shared across replicas), otherwise in process memory.
"""
import hashlib
import json
import os
import time
import uuid

try:
    import redis
except ImportError:
    redis = None

TTL = int(os.getenv("AGENTWALL_HITL_TTL", "3600"))
_PREFIX = "hitl:token:"


def fingerprint(call: dict) -> str:
    body = json.dumps([call.get("session_id"), call.get("agent_id"), call.get("tool_name"),
                       call.get("arguments")], sort_keys=True, default=str)
    return hashlib.sha256(body.encode()).hexdigest()


class HITLManager:
    _instance = None

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.redis_url = os.getenv("REDIS_URL")
        self._r = redis.from_url(self.redis_url, decode_responses=True) if (redis and self.redis_url) else None
        self.high_risk_tools = ["delete_db", "send_payment", "drop_table", "sudo_command"]
        self._local = {}

    # -- storage -------------------------------------------------------------
    def _get(self, token):
        if self._r:
            raw = self._r.get(_PREFIX + token)
            return json.loads(raw) if raw else None
        entry = self._local.get(token)
        if entry and time.time() - entry["ts"] > TTL:
            self._local.pop(token, None)
            return None
        return entry

    def _put(self, token, entry):
        if self._r:
            ttl = max(1, int(TTL - (time.time() - entry["ts"])))
            self._r.setex(_PREFIX + token, ttl, json.dumps(entry))
        else:
            self._local[token] = entry

    def _delete(self, token) -> bool:
        if self._r:
            return self._r.delete(_PREFIX + token) == 1  # only one caller wins the delete
        return self._local.pop(token, None) is not None

    # -- API -----------------------------------------------------------------
    def check_hitl_required(self, call: dict) -> dict:
        tool_name = str(call.get("tool_name", "")).lower()
        if not any(t in tool_name for t in self.high_risk_tools):
            return {"requires_hitl": False}
        token = str(uuid.uuid4())
        self._put(token, {
            "token": token, "session_id": call.get("session_id"), "agent_id": call.get("agent_id"),
            "tool_name": tool_name, "arguments": call.get("arguments"), "fingerprint": fingerprint(call),
            "ts": time.time(), "status": "PENDING",
        })
        return {"requires_hitl": True, "token": token,
                "reason": f"Tool '{tool_name}' requires human approval."}

    def pending(self) -> list:
        if self._r:
            entries = [self._get(k[len(_PREFIX):]) for k in self._r.scan_iter(_PREFIX + "*")]
        else:
            entries = [self._get(t) for t in list(self._local)]
        return sorted((e for e in entries if e and e["status"] == "PENDING"), key=lambda e: e["ts"])

    def decide(self, token: str, approve: bool) -> bool:
        entry = self._get(token)
        if not entry or entry["status"] != "PENDING":
            return False
        entry["status"] = "APPROVED" if approve else "DENIED"
        self._put(token, entry)
        return True

    def consume(self, token: str, call: dict) -> bool:
        """True once, for an approved token whose fingerprint matches this exact call."""
        entry = self._get(token)
        if not entry or entry["status"] != "APPROVED" or entry["fingerprint"] != fingerprint(call):
            return False
        return self._delete(token)
