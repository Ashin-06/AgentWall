# 🏗️ AgentWall Architecture

AgentWall provides process attribution and traffic monitoring for AI agents. It uses process heuristics and protocol-specific proxies to capture interactions without TLS interception.

## 1. Natural Attribution Engine
The core of AgentWall is a heuristic engine that monitors the operating system's process table and file system events. It utilizes **scikit-learn** for anomaly detection in the attribution layer to identify deviations from baseline agent behavior.

- **Process Monitoring**: AgentWall identifies known AI agents (VS Code, Cursor, Aider) by their process name, command-line arguments, and parent-child relationships.
- **Event Correlation**: When a file is modified, AgentWall correlates the timestamp with the active AI processes to "attribute" the change to the specific agent responsible.
- **Zero Config**: This works out-of-the-box without needing to install CA certificates or modify IDE network settings.

## 2. Universal AI Gateway
To monitor "Thoughts" (LLM requests), AgentWall provides a protocol-agnostic gateway.

- **Unified Interface**: Supports OpenAI, Anthropic, and Google Gemini API formats.
- **Transparent Interception**: Agents point their `base_url` to AgentWall (e.g., `http://localhost:8000/v1`).
- **Forensic Logging**: Every request and response is logged into a HMAC-chained audit log for tamper-proof forensics.

## 3. The Forensic SOC Dashboard
A real-time React interface that visualizes:
- **Live Sessions**: Current active agent interactions.
- **MITRE ATT&CK Mapping**: High-risk behaviors mapped to standard techniques.
- **Session Replay**: Forensic step-by-step playback of agent actions.
- **Attack Graphs**: Visual causality chains of agent behavior.

## 4. Immutable Telemetry Pipeline
- **DuckDB Backend**: High-performance analytical storage for millions of events.
- **Asynchronous Queuing**: Ensures the security core never slows down agent execution.
- **HMAC Chaining**: Each log entry is cryptographically linked to the previous one, ensuring any modification is immediately detectable.
