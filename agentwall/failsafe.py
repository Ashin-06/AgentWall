"""
Failsafe wrapper around the proxy.

If AgentWall itself crashes, has a bug, or is overloaded,
you need a defined behaviour:
  fail_open  = let all calls through (availability > security)
  fail_closed = block all calls (security > availability)

Configure: AGENTWALL_FAIL_MODE=open|closed  (default: closed)

Also implements a timeout on the ENTIRE pipeline evaluation
so a slow LLM call can't hold up agent execution indefinitely.
"""
import asyncio
import os
import traceback


FAIL_MODE          = os.getenv("AGENTWALL_FAIL_MODE", "closed")
PIPELINE_TIMEOUT   = float(os.getenv("AGENTWALL_PIPELINE_TIMEOUT", "2.0"))  # seconds


class FailsafeProxy:
    def __init__(self, inner_proxy):
        self.proxy     = inner_proxy
        self.raw_proxy = inner_proxy
        self.fail_mode = FAIL_MODE
        self.timeout   = PIPELINE_TIMEOUT

    async def evaluate(self, payload: dict) -> dict:
        try:
            return await asyncio.wait_for(
                self.proxy.evaluate(payload),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            verdict = "PERMIT" if self.fail_mode == "open" else "BLOCK"
            reason  = f"AgentWall pipeline timeout ({self.timeout}s) — failing {self.fail_mode}"
            print(f"[Failsafe] WARNING: {reason}")
            return {
                "verdict":  verdict,
                "reason":   reason,
                "event_id": "timeout",
                "failsafe": True,
                "fail_mode": self.fail_mode,
            }
        except Exception as e:
            verdict = "PERMIT" if self.fail_mode == "open" else "BLOCK"
            reason  = f"AgentWall internal error — failing {self.fail_mode}"
            print(f"[Failsafe] ERROR: Internal error: {e}")
            traceback.print_exc()
            return {
                "verdict":  verdict,
                "reason":   reason,
                "event_id": "error",
                "failsafe": True,
                "error":    str(e),
            }

    async def sanitise_output(self, payload: dict) -> dict:
        try:
            return await asyncio.wait_for(
                self.proxy.sanitise_output(payload),
                timeout=1.0,  # output sanitisation must be fast
            )
        except Exception:
            # On failure, return output unchanged
            return {"output": payload.get("output", ""), "sanitised": False,
                    "failsafe": True}
