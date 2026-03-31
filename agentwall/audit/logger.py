"""Thin wrapper around schema.write_event — v2 passes mitre_id and latency."""
from agentwall.audit.schema import write_event, KEY_ID
from agentwall.audit.write_queue import DBWriteQueue
import logging

class AuditLogger:
    def __init__(self):
        self.logger = logging.getLogger("agentwall.audit")
        self.logger.setLevel(logging.INFO)

    async def log(self, event: dict) -> str:
        """Helper to log a complete event dictionary (used by proxy.py)."""
        return await self.write(
            session_id=event.get("session_id", "default"),
            agent_id=event.get("agent_id", "default"),
            call_id=event.get("event_id", ""),
            tool_name=event.get("tool_name", "unknown"),
            arguments=event.get("arguments", {}),
            verdict=event.get("verdict", "AUDIT"),
            reason=event.get("reason", ""),
            details=event.get("details", {}),
            mitre_id=event.get("mitre_id", ""),
            latency_ms=event.get("latency_ms", 0),
        )

    async def write(
        self,
        session_id: str, agent_id: str, call_id: str,
        tool_name: str, arguments: dict,
        verdict: str, reason: str, details: dict,
        mitre_id: str = "", source_fmt: str = "unknown",
        latency_ms: float = 0, shadow_block: bool = False,
    ) -> str:
        # Extract mitre_id from details if not passed directly
        if not mitre_id and isinstance(details, dict):
            mitre_id = details.get("mitre_id", "")
        lms = latency_ms or (details.get("latency_ms", 0) if isinstance(details, dict) else 0)
        
        row = (
            session_id, agent_id, call_id, tool_name,
            arguments, verdict, reason, details,
            mitre_id, source_fmt, float(lms), shadow_block, KEY_ID
        )
        return await DBWriteQueue.get().write(row)
