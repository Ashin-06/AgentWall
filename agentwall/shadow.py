"""
Shadow Mode — observe-only operation.

In shadow mode, AgentWall evaluates every call through all 5 layers
but NEVER blocks — it only logs what WOULD have been blocked.

Use this during rollout to:
  1. Collect baseline data without disrupting agents
  2. Tune detection thresholds
  3. Identify false positives before going live
  4. Build the Isolation Forest on real traffic before enforcing anomaly detection

Enable per-request: set header X-AgentWall-Shadow: true
Enable globally: set env AGENTWALL_SHADOW_MODE=1
"""
import os


class ShadowMode:
    def __init__(self, proxy):
        self.proxy   = proxy
        self.enabled = os.getenv("AGENTWALL_SHADOW_MODE", "0") == "1"

    async def observe(self, payload: dict) -> dict:
        """Run full evaluation but override any BLOCK to SHADOW_BLOCK."""
        result = await self.proxy.evaluate(payload)
        original_verdict = result["verdict"]

        if original_verdict == "BLOCK":
            result["verdict"]       = "PERMIT"
            result["shadow_block"]  = True
            result["shadow_reason"] = result["reason"]
            result["reason"]        = "Shadow mode: would have been BLOCKED"

        result["shadow_mode"] = True
        return result
