# AgentWall Roadmap

This document outlines the planned future trajectory of the AgentWall project, transitioning from a robust single-node telemetry tool to an enterprise-grade, distributed AI security firewall.

## Phase 1: High Availability & Enterprise Scaling (Q3 2026)
The current architecture uses DuckDB for localized, high-performance analytical telemetry and an in-memory fallback for Human-in-the-Loop (HITL) approval caching. The next phase will introduce distributed state management:

- **Redis Integration**: Fully transition the HITL token management to Redis (`redis==5.0.4`) to support multi-pod deployments and horizontal scaling of the proxy layer.
- **PostgreSQL Persistence**: Migrate the primary transactional data store from DuckDB to PostgreSQL (`psycopg2-binary==2.9.9`), utilizing the existing async queue architecture to prevent database locking under enterprise loads.
- **Gunicorn Workloads**: Official documentation and Helm charts supporting `gunicorn` deployments with `uvicorn` workers.

## Phase 2: Evaluation Framework (`evals/`) (Q4 2026)
To prove the efficacy of the Natural Attribution engine and the Policy Enforcement layer, a dedicated evaluation suite is planned:

- **Automated Agent Benchmarking**: Scripts that spawn isolated Docker containers running various AI agents (Aider, OpenDevin, Cursor) to deliberately attempt policy violations (e.g., prompt injections, unauthorized file exfiltration).
- **Red Team Payloads**: An open-source collection of adversarial payloads designed specifically to test the boundaries of LLM tool-use restrictions.

## Phase 3: Advanced Heuristics & Anomaly Detection (Q1 2027)
While the current system uses rule-based policies and heuristic process matching, the future roadmap includes statistical anomaly detection:

- **Scikit-Learn Integration**: Activate the `scikit-learn` integration to establish moving baselines of "normal" agent behavior (e.g., standard tool usage frequencies, typical execution latency, expected geographic targets).
- **Deviation Alerts**: Trigger automated `AUDIT` flags when an agent deviates significantly from its historical behavioral baseline, even if no explicit rule is violated.

## Contributing
We welcome contributions to help accelerate this roadmap. Please check the open issues for specific tasks related to Redis, PostgreSQL, and the Evals framework.
