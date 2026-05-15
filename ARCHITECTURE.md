# AgentWall Architecture

AgentWall provides process attribution and traffic monitoring for AI agents. It uses a multi-layer inspection pipeline to intercept, attribute, analyze, and enforce policy on all agent-generated tool calls without TLS interception.

---

## 1. Natural Attribution Engine (NAE)

The core technical contribution of AgentWall. The NAE solves the attribution problem — *given a file-system modification at time T, which of N active AI agent processes caused it?* — without requiring TLS interception, which would break most IDE integrations.

### Multi-Signal Attribution (MSA) Algorithm

The NAE uses a three-phase weighted voting approach formalized as the **MSA Algorithm** (see [ATTRIBUTION.md](ATTRIBUTION.md) for full pseudocode and conflict resolution policy):

**Phase 1 — Candidate Filtering**: Scan the OS process table via `psutil` and retain only processes matching known AI agent signatures (VS Code, Cursor, Aider, etc.).

**Phase 2 — Signal Scoring**: For each candidate process, compute a weighted score using 4 signals:

| Signal | Weight | Rationale |
|---|---|---|
| Open File Handle | 1.0 | OS-verified: process holds the file descriptor |
| CPU Activity (within W=2s window) | 0.6 | Agent actively computing implies write activity |
| Process Name Signature Match | 0.3 | Heuristic prior |
| Child of Known Launcher | 0.4 | Extension hosts inherit parent identity |

**Phase 3 — Conflict Resolution**: If scores are tied (multiple agents active simultaneously), the most recently active process wins. A `contested` flag is raised if ambiguity remains.

### Attribution Accuracy (Experimental Results)

| Scenario | Accuracy | Contested Flag Rate |
|---|---|---|
| Single agent, distinct file | 100% | 0% |
| Dual agent, distinct files | 100% | 0% |
| Dual agent, same file (worst case) | Best-effort | 100% ✅ |
| P99 attribution latency | — | 0.01 ms |

Source: `evals/attribution_accuracy.py`

### Process Monitoring
- AgentWall identifies known AI agents by process name, command-line arguments, and parent-child relationships.
- Zero Config: No CA certificate installation or IDE network modification required.
- File-system events are captured by `watchdog` and correlated with the process table snapshot.

---

## 2. Universal AI Gateway (Proxy)

To monitor LLM "Thoughts" (API requests), AgentWall provides a protocol-agnostic gateway.

- **Unified Interface**: Supports OpenAI (`/v1/chat/completions`), Anthropic (`/v1/messages`), and Google Gemini API formats via protocol normalization.
- **Transparent Interception**: Agents point their `base_url` to AgentWall (`http://localhost:8000/v1`).
- **Layered Pipeline**: Every intercepted call passes through a 4-layer inspection pipeline before forwarding.

---

## 3. Layered Security Pipeline

```
Inbound Call
     │
     ▼
[Layer 1: PolicyEngine]   ← YAML rules, glob/regex matching, per-agent RBAC
     │ BLOCK / continue
     ▼
[Layer 2: Anomaly + Trust]  ← Isolation Forest, Trust Graph, RAG Poison, Causal Graph
     │ flag / continue
     ▼
[Layer 3: Semantic Engine]  ← LLM-assisted injection classification
     │ score / continue
     ▼
[Layer 4: Campaign Detect] ← SimHash clustering of attack patterns across sessions
     │
     ▼
[Active Defense]           ← Honeytoken check (100% confidence, 0% FPR)
     │
     ▼
[Audit Log]                ← HMAC-chained DuckDB write (non-blocking async queue)
     │
     ▼
[Forward to LLM API]
```

---

## 4. Forensic SOC Dashboard

A real-time React interface that visualizes:
- **Live Sessions**: Current active agent interactions with per-agent risk scores.
- **MITRE ATT&CK Mapping**: High-risk behaviors mapped to ATT&CK techniques automatically.
- **Session Replay**: Forensic step-by-step playback of agent actions with full argument capture.
- **Attack Graphs**: Causal chain visualization of coordinated agent behavior.
- **Campaign Correlation**: Automated detection of multi-session attack patterns via SimHash.

---

## 5. Immutable Telemetry Pipeline

- **DuckDB Backend**: High-performance embedded analytical database. Ideal for event-heavy workloads with complex aggregation queries (MITRE heatmaps, latency percentiles, session replay).
- **Asynchronous Write Queue**: Events are written via a non-blocking async queue (`audit/write_queue.py`) to ensure the security core never adds latency to agent execution.
- **HMAC Chaining**: Each log entry includes `chain_hash = HMAC-SHA256(HMAC_KEY, prev_hash || event_data)`. Any tampering with a past record breaks the chain, detectable via the verification procedure in [VERIFICATION.md](VERIFICATION.md).
- **Key Rotation Support**: The `key_id` column allows cryptographic key rotation without invalidating historical records.

---

## 6. Threat Model Summary

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full STRIDE analysis.

**Explicitly Protected Against:**
- LLM-assisted exfiltration via tool calls (policy engine + honeytokens)
- Privilege escalation via agent delegation chain (trust graph)
- Log tampering (HMAC chain)
- Anomalous agent behavior drift (Isolation Forest)

**Explicitly Out of Scope:**
- Proxy-aware bypass (agent detects proxy and routes directly) — requires OS-level iptables/eBPF
- Physical host compromise
- Model-level poisoning
