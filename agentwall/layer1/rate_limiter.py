"""
Per-agent rate limiter with circuit breaker and Token Bucket algorithm.

If an agent makes > N tool calls in T seconds, it's likely either:
  - A runaway agent (bug) → circuit break
  - An attack generating high call volume → block + alert

Circuit breaker states: CLOSED (normal) → OPEN (blocking) → HALF_OPEN (testing)
Uses a Token Bucket algorithm for precise traffic shaping.
"""
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum


class CBState(Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


# Default limits — override per-agent in policy.yaml
DEFAULT_LIMITS = {
    "calls_per_minute":  500,
    "calls_per_second":  50,
    "cb_threshold":      20,   # failures before open
    "cb_recovery_secs":  10,   # time before HALF_OPEN
}


@dataclass
class TokenBucket:
    capacity: float
    rate: float
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.time)

    def consume(self, amount: float = 1.0) -> bool:
        now = time.time()
        refill = (now - self.last_refill) * self.rate
        self.tokens = min(self.capacity, self.tokens + refill)
        self.last_refill = now
        
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


@dataclass
class AgentState:
    sec_bucket: TokenBucket = None
    min_bucket: TokenBucket = None
    cb_state: CBState = CBState.CLOSED
    cb_opened_at: float = 0.0
    cb_failures: int = 0


class RateLimiter:
    def __init__(self, limits: dict = None):
        self.limits = {**DEFAULT_LIMITS, **(limits or {})}
        self._states: dict[str, AgentState] = defaultdict(lambda: AgentState(
            sec_bucket=TokenBucket(self.limits["calls_per_second"], self.limits["calls_per_second"]),
            min_bucket=TokenBucket(self.limits["calls_per_minute"], self.limits["calls_per_minute"]/60),
            tokens=self.limits["calls_per_second"] # Start full
        ))
        # Fix: The above defaultdict lambda was slightly wrong in previous thought, Correcting below.

    def _get_state(self, agent_id: str) -> AgentState:
        if agent_id not in self._states:
            self._states[agent_id] = AgentState(
                sec_bucket=TokenBucket(self.limits["calls_per_second"], self.limits["calls_per_second"], tokens=self.limits["calls_per_second"]),
                min_bucket=TokenBucket(self.limits["calls_per_minute"], self.limits["calls_per_minute"]/60, tokens=self.limits["calls_per_minute"])
            )
        return self._states[agent_id]

    def check(self, call: dict) -> dict:
        agent_id = call["agent_id"]
        now      = time.time()
        state    = self._get_state(agent_id)

        # Circuit breaker logic
        if state.cb_state == CBState.OPEN:
            if now - state.cb_opened_at > self.limits["cb_recovery_secs"]:
                state.cb_state = CBState.HALF_OPEN
            else:
                return {"blocked": True, "reason": "Circuit breaker OPEN — agent rate limit exceeded"}

        # Check per-second bucket
        if not state.sec_bucket.consume():
            state.cb_failures += 1
            if state.cb_failures >= self.limits["cb_threshold"]:
                state.cb_state     = CBState.OPEN
                state.cb_opened_at = now
            return {"blocked": True,
                    "reason": f"Rate limit: Exceeded {self.limits['calls_per_second']} calls/sec"}

        # Check per-minute bucket
        if not state.min_bucket.consume():
            return {"blocked": True,
                    "reason": f"Rate limit: Exceeded {self.limits['calls_per_minute']} calls/min"}

        # Reset failures on success
        if state.cb_state == CBState.HALF_OPEN:
            state.cb_state    = CBState.CLOSED
            state.cb_failures = 0

        return {"blocked": False}
