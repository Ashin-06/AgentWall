"""
Prometheus metrics for AgentWall.

Exposes /metrics in standard Prometheus text format.
Plug into Grafana / Datadog / any observability stack.

Metrics:
  agentwall_calls_total{verdict, tool, agent}
  agentwall_latency_seconds{path}  (histogram)
  agentwall_injection_score        (histogram)
  agentwall_anomaly_score          (histogram)
  agentwall_queue_size             (gauge)
  agentwall_active_campaigns       (gauge)
  agentwall_policy_violations_total{rule}
  agentwall_mitre_hits_total{technique}
  agentwall_agent_blocks_total{agent}
  agentwall_tool_calls_total{tool}
  agentwall_block_rate             (gauge, rolling)
"""
import time
from collections import defaultdict, Counter
from typing import Dict, List


class MetricsRegistry:
    """Minimal Prometheus-compatible metrics (no external deps)."""
    _instance = None

    @classmethod
    def get(cls) -> "MetricsRegistry":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._counters:   Dict[str, Counter] = defaultdict(Counter)
        self._histograms: Dict[str, List]    = defaultdict(list)
        self._gauges:     Dict[str, float]   = {}
        self._start_time = time.time()

    # ── Record methods ────────────────────────────────────────────────────────

    def inc(self, name: str, labels: dict = None, value: float = 1):
        key = self._label_key(labels)
        self._counters[name][key] += value

    def observe(self, name: str, value: float, labels: dict = None):
        """Record a histogram observation."""
        key = self._label_key(labels)
        self._histograms[f"{name}#{key}"].append(value)
        # Keep only last 10k observations per series
        if len(self._histograms[f"{name}#{key}"]) > 10_000:
            self._histograms[f"{name}#{key}"] = \
                self._histograms[f"{name}#{key}"][-5_000:]

    def set_gauge(self, name: str, value: float, labels: dict = None):
        key = self._label_key(labels)
        self._gauges[f"{name}#{key}"] = value

    # ── Convenience recorders ─────────────────────────────────────────────────

    def record_call(self, verdict: str, tool_name: str,
                    agent_id: str, latency_ms: float,
                    inj_score: float = 0, anom_score: float = 0):
        self.inc("agentwall_calls_total",
                 {"verdict": verdict, "tool": tool_name[:30], "agent": agent_id[:30]})
        path = "fast" if latency_ms < 5 else "ml" if latency_ms < 100 else "llm"
        self.observe("agentwall_latency_seconds", latency_ms / 1000,
                     {"path": path, "verdict": verdict})
        if inj_score > 0:
            self.observe("agentwall_injection_score", inj_score)
        if anom_score > 0:
            self.observe("agentwall_anomaly_score", anom_score)

    def record_policy_violation(self, rule_name: str):
        self.inc("agentwall_policy_violations_total", {"rule": rule_name[:50]})

    def record_mitre(self, mitre_id: str):
        """Track per-MITRE-technique hit counts."""
        if mitre_id and mitre_id not in ("", "T0000"):
            self.inc("agentwall_mitre_hits_total", {"technique": mitre_id})

    def record_agent_block(self, agent_id: str):
        """Track blocks per agent for risk scoring."""
        self.inc("agentwall_agent_blocks_total", {"agent": agent_id[:40]})

    def record_tool_call(self, tool_name: str):
        """Track raw tool call frequency."""
        self.inc("agentwall_tool_calls_total", {"tool": tool_name[:30]})

    def update_gauges(self, queue_size: int = 0, active_campaigns: int = 0):
        self.set_gauge("agentwall_queue_size", queue_size)
        self.set_gauge("agentwall_active_campaigns", active_campaigns)

    # ── Prometheus text format renderer ──────────────────────────────────────

    def uptime(self) -> float:
        """Returns seconds since registry initialization."""
        return time.time() - self._start_time

    def render(self) -> str:
        # ... existing code ...
        return "\n".join(lines) + "\n"

    def export(self) -> str:
        """Alias for render() to match main.py expectations."""
        return self.render()

    @staticmethod
    def _label_key(labels: dict | None) -> str:
        if not labels:
            return ""
        return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))

    @staticmethod
    def _format_labels(label_key: str) -> str:
        if not label_key:
            return ""
        parts = []
        for pair in label_key.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                parts.append(f'{k}="{v}"')
        return ",".join(parts)
