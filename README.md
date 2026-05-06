# AgentWall

AgentWall is a security layer for monitoring and controlling autonomous AI agents. It provides process attribution, traffic interception, and policy enforcement for LLM-integrated tools and IDEs.

## Technical Overview

AgentWall operates as a transparent or explicit proxy between AI agents and their LLM providers. It captures tool calls, inspects arguments, and applies security policies before allowing traffic to proceed.

### Core Components

- **Interception Proxy**: Supports OpenAI, Anthropic, and Google Gemini protocols. Intercepts `/v1/chat/completions` and `/v1/messages` endpoints.
- **Natural Attribution Engine**: Uses system-level process monitoring (`psutil`) and file-system watching (`watchdog`) to correlate file modifications with specific agent processes (e.g., VS Code, Cursor, Aider).
- **Policy Engine**: Evaluates JSON/YAML based rules to determine if a tool call should be permitted, audited, or blocked.
- **Audit System**: Stores every interaction in a DuckDB database. Events are HMAC-chained to ensure log integrity.
- **Active Defense**: Implements honeytoken decoys (fake credentials) to detect and block data exfiltration attempts.
- **SOC Dashboard**: A React-based interface for real-time telemetry, session forensic replay, and MITRE ATT&CK technique mapping.

## Features

- **Protocol Support**: Multi-provider support for OpenAI, Anthropic, and Google.
- **Process Correlation**: Heuristic identification of active AI agents on the host system.
- **Verification Modes**:
  - **Audit**: Log events without blocking.
  - **Enforce**: Actively block tool calls that violate security policies.
- **Observability**: Exposes system metrics in Prometheus format for integration with standard monitoring stacks.
- **Session Forensics**: Complete playback of agent-environment interactions for security auditing.

### **⚠️ Technical Limitations**
- **Manual Integration**: AgentWall is not a transparent network firewall. It requires AI agents to be explicitly pointed at the proxy endpoint (e.g., via `base_url`).
- **TLS/HTTPS**: Agents that hardcode provider URLs and do not support custom base URLs will bypass the monitoring layer.
- **Heuristic Attribution**: Process correlation is based on system-level heuristics and may produce false attributions in high-concurrency environments.

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

## Documentation
- [Architecture](ARCHITECTURE.md): Detailed technical design and data flow.
- [Configuration](CONFIGURATION.md): Policy syntax and environment variables.
- [Verification](VERIFICATION.md): Procedures for testing security controls.

---
License: MIT
