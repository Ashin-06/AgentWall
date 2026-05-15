"""
Distributed HITL Manager using Redis.
Ensures approval tokens are shared across all pods.
"""
import uuid
import os
import json
try:
    import redis
except ImportError:
    redis = None
import time

class HITLManager:
    _instance = None

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.redis_url = os.getenv("REDIS_URL")
        self._r = None
        if redis and self.redis_url:
            self._r = redis.from_url(self.redis_url, decode_responses=True)
            print(f"[HITLManager] Connected to Redis: {self.redis_url}")
        elif self.redis_url:
            print(f"[HITLManager] WARNING: REDIS_URL is set but 'redis' package is not installed. Falling back to local cache.")
        
        self.high_risk_tools = ["delete_db", "send_payment", "drop_table", "sudo_command"]
        self._local_cache = {} # Fallback

    def check_hitl_required(self, call: dict) -> dict:
        tool_name = call.get("tool_name", "").lower()
        
        if any(risk_tool in tool_name for risk_tool in self.high_risk_tools):
            token = str(uuid.uuid4())
            hitl_data = {
                "session_id": call["session_id"],
                "agent_id": call["agent_id"],
                "tool_name": tool_name,
                "ts": time.time(),
                "status": "PENDING"
            }
            
            if self._r:
                self._r.setex(f"hitl:token:{token}", 3600, json.dumps(hitl_data))
            else:
                self._local_cache[token] = hitl_data
                
            return {
                "requires_hitl": True,
                "token": token,
                "reason": f"Tool '{tool_name}' requires human approval."
            }
            
        return {"requires_hitl": False}

    def verify_approval(self, token: str) -> bool:
        """Checks if a token has been approved by a human."""
        if self._r:
            data = self._r.get(f"hitl:token:{token}")
            if data:
                return json.loads(data).get("status") == "APPROVED"
        else:
            return self._local_cache.get(token, {}).get("status") == "APPROVED"
        return False

    def approve_token(self, token: str):
        """Called by the management API/Dashboard."""
        if self._r:
            data = self._r.get(f"hitl:token:{token}")
            if data:
                payload = json.loads(data)
                payload["status"] = "APPROVED"
                self._r.setex(f"hitl:token:{token}", 3600, json.dumps(payload))
        else:
            if token in self._local_cache:
                self._local_cache[token]["status"] = "APPROVED"
