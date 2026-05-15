# AgentWall

[![Build Status](https://github.com/Ashin-06/AgentWall/actions/workflows/verify.yml/badge.svg)](https://github.com/Ashin-06/AgentWall/actions/workflows/verify.yml)

AgentWall is an AI agent security firewall — a transparent proxy that sits between autonomous coding agents (Copilot, Cursor, Aider) and their upstream LLM APIs. It performs process attribution, policy enforcement, tamper-proof audit logging, and real-time SOC-style forensics.

The core research problem it addresses: **how do you monitor and control autonomous AI agents that act on your behalf without breaking their workflow?**

---

## Research Contributions

AgentWall makes the following novel contributions to the AI security literature:

1. **Natural Attribution Engine (NAE)** — A zero-config, OS-level process attribution system that uses `psutil` process monitoring and `watchdog` filesystem event correlation to identify which AI agent caused a file modification — without TLS interception or agent-side instrumentation. This is formalized as the Multi-Signal Attribution (MSA) algorithm (see [ATTRIBUTION.md](ATTRIBUTION.md)).

2. **HMAC-Chained Audit Logs** — Each audit log entry is cryptographically linked to its predecessor via HMAC-SHA256, creating a tamper-evident forensic chain borrowing from blockchain audit-trail techniques, applied specifically to AI agent forensics.

3. **Honeytoken Active Defense** — Fake credentials are injected into the agent's environment context. Any use of these credentials is a confirmed zero-false-positive attack signal — a technique from traditional deception security, applied for the first time to AI agent traffic.

4. **MITRE ATT&CK Mapping for AI Agents** — Autonomous AI agent behaviors are automatically mapped to the MITRE ATT&CK framework, providing a standardized vocabulary for AI agent threat reporting.

---

## Evaluation Results

Results are from controlled experiments in `evals/`. All numbers are reproducible by running the scripts locally.

### Policy Engine Evaluation (`evals/run_benchmarks.py`)

| Metric | Result | Dataset | Methodology |
|---|---|---|---|
| True Positive Rate (TPR) | **100%** | 25 malicious samples | Layer 1 policy rules only; ML layers (Anomaly, RAG, Injection) mocked |
| False Positive Rate (FPR) | **0%** | 25 benign samples | Layer 1 policy rules only; ML layers mocked |
| End-to-End Intercept Latency | **~25 ms** | 50 calls total | Real FastAPI TestClient, in-memory DuckDB |

> **Note**: TPR/FPR measure Layer 1 (deterministic YAML policy rules) only. The ML-based layers (Layer 2 anomaly detection, Layer 3 semantic injection) are mocked in CI to avoid requiring a running LLM. A full end-to-end evaluation including ML layers requires a live Ollama instance.

### Attribution Algorithm Validation (`evals/attribution_accuracy.py`)

| Scenario | Result | Methodology |
|---|---|---|
| Single-agent attribution logic | **100% correct** | Simulated oracle (50 trials) |
| Dual-agent, distinct file paths | **100% correct** | Simulated oracle (40 trials) |
| Concurrent writes, same file | **Contested flag raised 100%** | Simulated oracle (10 trials) |
| Algorithm overhead (P99) | **< 0.05 ms** | Simulated oracle, no psutil I/O |

> **Note**: These results validate the MSA *algorithm logic* (scoring, tiebreaking, contested-flag) using a deterministic simulation. They do **not** measure psutil process-scanning latency on real OS processes. See [ATTRIBUTION.md](ATTRIBUTION.md) for full methodology details.

---

## Architecture

AgentWall operates as a transparent or explicit proxy between AI agents and their LLM providers. It captures tool calls, inspects arguments, and applies a layered security pipeline before allowing traffic to proceed.

### Core Components

- **Interception Proxy**: Supports OpenAI, Anthropic, and Google Gemini protocols. Intercepts `/v1/chat/completions` and `/v1/messages` endpoints.
- **Natural Attribution Engine**: Uses OS-level process monitoring (`psutil`) and filesystem watching (`watchdog`) to correlate file modifications with specific agent processes. Implements the Multi-Signal Attribution (MSA) algorithm.
- **Policy Engine (Layer 1)**: Evaluates compiled YAML rules to determine if a tool call should be permitted, audited, or blocked. Supports glob patterns, regex conditions, and per-agent scoping.
- **Multi-Layer Detection (Layers 2–4)**: Temporal anomaly detection (Isolation Forest), RAG poisoning detection, trust graph confusion-deputy defense, and campaign correlation.
- **Semantic Injection Engine (Layer 3)**: LLM-assisted classification of prompt injection attempts.
- **Audit System**: Stores every interaction in DuckDB. Events are HMAC-chained to ensure log integrity.
- **Active Defense**: Honeytoken decoys (fake credentials) for zero-FPR exfiltration detection.
- **SOC Dashboard**: A React-based interface for real-time telemetry, session forensic replay, and MITRE ATT&CK technique mapping.

### Layered Security Model

```
Agent ──► [Layer 1: Policy Engine] ──► [Layer 2: Anomaly/Trust] ──► [Layer 3: Semantic] ──► LLM API
                │                              │                           │
                ▼                              ▼                           ▼
          AUDIT / BLOCK              Anomaly Score / Flag        Injection Score / Flag
```

---

## Technical Limitations (Honest Threat Model)

Full threat model available in [THREAT_MODEL.md](THREAT_MODEL.md).

- **Manual Integration**: AgentWall is not a transparent network firewall. It requires AI agents to be pointed at the proxy endpoint (e.g., via `base_url`).
- **TLS/HTTPS**: Agents that hardcode provider URLs cannot be intercepted without OS-level firewall rules.
- **Proxy-Aware Bypass**: A sophisticated agent that detects it is being proxied could route around it. This is a deliberate design trade-off to avoid breaking IDE integrations.
- **Heuristic Attribution**: Process correlation is based on system-level heuristics and may produce contested attribution in high-concurrency environments (handled via `contested` flag).

---

## Comparison to Related Work

See [COMPARISON.md](COMPARISON.md) for a structured comparison against LiteLLM, Guardrails-AI, and OWASP LLM Top 10 mitigations.

---

## Installation

### Prerequisites
- Python 3.10 or higher
- Node.js (only required for rebuilding the dashboard)

### Setup
1. Clone the repository and navigate to the directory.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure environment variables in `.env` (refer to `.env.example`).
4. (Optional) Run `install.bat` on Windows for automated setup.

---

## Usage

Start the AgentWall server:
```bash
python -m uvicorn agentwall.main:app --host 0.0.0.0 --port 8000 --ws websockets
```

### Dashboard Access
The dashboard is served at `http://localhost:8000`.  
Authentication is required (Default: `admin`).

### Integration
Point your AI agent's base URL to the AgentWall proxy:
- **Base URL**: `http://localhost:8000/v1`

---

## Running Evaluations

```bash
# Security policy evaluation (TPR/FPR)
python evals/run_benchmarks.py

# Attribution accuracy experiment
python evals/attribution_accuracy.py

# Full unit test suite
python -m pytest tests/
```

---

## Documentation

| Document | Description |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Detailed technical design and data flow |
| [ATTRIBUTION.md](ATTRIBUTION.md) | Formal specification of the NAE algorithm |
| [THREAT_MODEL.md](THREAT_MODEL.md) | STRIDE threat model and security boundary analysis |
| [COMPARISON.md](COMPARISON.md) | Comparison against related work (LiteLLM, Guardrails-AI) |
| [CONFIGURATION.md](CONFIGURATION.md) | Policy syntax and environment variables |
| [ROADMAP.md](ROADMAP.md) | Future work and research directions |
| [VERIFICATION.md](VERIFICATION.md) | Procedures for testing security controls |

---

License: MIT
