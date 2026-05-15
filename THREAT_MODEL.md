# THREAT_MODEL.md — AgentWall Threat Model

## Framework: STRIDE

This document applies the STRIDE threat modeling framework to the AgentWall security system. It defines the assets being protected, the adversary model, what AgentWall explicitly protects against, and what it explicitly does **not** protect against.

---

## 1. Assets Under Protection

| Asset | Description | Value |
|---|---|---|
| LLM API Keys | Credentials used by agents to call GPT-4, Claude, etc. | High |
| Source Code | Files modified by coding agents | High |
| Production Secrets | `.env` files, database passwords, SSH keys | Critical |
| Audit Log Integrity | Tamper-evident record of all agent actions | High |
| Agent Behavior | Detection of unexpected or malicious tool calls | High |

---

## 2. Adversary Model

AgentWall's primary adversary is a **compromised AI agent** — an autonomous agent that has been manipulated (via prompt injection, supply chain attack, or model compromise) to perform actions contrary to the user's intent.

### Adversary Types

| Type | Description | Sophistication |
|---|---|---|
| Naive Exfiltrator | Agent manipulated by prompt injection; sends secrets to external URL | Low |
| Policy-Aware Bypasser | Agent that detects it's being proxied and changes `base_url` | Medium |
| Slow Exfiltrator | Agent that leaks data gradually across many small tool calls | Medium |
| Supply Chain Attacker | Malicious agent package installed via `pip install` | High |
| Insider Threat | Developer who deliberately bypasses AgentWall to hide actions | High |

---

## 3. STRIDE Analysis

### S — Spoofing Identity

| Threat | AgentWall Response |
|---|---|
| Agent claims to be a different agent (`agent_id` manipulation) | **Partially Mitigated**: `agent_id` is caller-supplied. The NAE cross-validates against OS process table. A mismatch raises an AUDIT event. |
| Rogue process spoofs a known agent name | **Mitigated**: Process table cross-validation via `psutil` checks PID, parent PID, and binary path — not just the process name string. |

### T — Tampering

| Threat | AgentWall Response |
|---|---|
| Attacker modifies audit logs to hide actions | **Mitigated**: HMAC-chained log entries. Any modification of a past event breaks the chain hash, detectable via `VERIFICATION.md` procedure. |
| Attacker modifies `policy.yaml` to weaken rules | **Mitigated**: Policy file changes trigger a reload event that is itself logged. Production deployments should use read-only filesystem mounts. |
| Agent manipulates its tool call arguments after inspection | **NOT Mitigated**: AgentWall inspects the call at the proxy boundary. If the agent has a side-channel to call the real API directly, the manipulation occurs outside inspection scope. |

### R — Repudiation

| Threat | AgentWall Response |
|---|---|
| Agent denies having made a tool call | **Mitigated**: Every call is logged with timestamp, session_id, agent_id, and HMAC chain hash. The chain provides non-repudiation of the log record itself. |
| User claims agent was not acting on their behalf | **Partially Mitigated**: Session replay provides evidence. Intent scoring (`alignment/intent_scorer.py`) assesses goal alignment. |

### I — Information Disclosure

| Threat | AgentWall Response |
|---|---|
| Agent exfiltrates secrets via `http_post` | **Mitigated**: Honeytoken detection (`honey.py`) catches use of injected fake credentials. Policy engine blocks known exfiltration endpoints. |
| Agent reads sensitive files (`/etc/passwd`, `.env`) | **Mitigated**: Policy rules with `contains: /etc/` and `contains: .env` block and log these attempts. |
| AgentWall dashboard exposes all agent traffic | **Mitigated**: JWT authentication required. HTTPS recommended for production (see `CONFIGURATION.md`). |

### D — Denial of Service

| Threat | AgentWall Response |
|---|---|
| Agent makes millions of calls to exhaust API quota | **Mitigated**: Rate limiter (`layer1/rate_limiter.py`) enforces per-agent call rate limits. |
| Agent sends massive payloads to fill audit log | **Partially Mitigated**: DuckDB handles large datasets efficiently. Payload size limits enforced at the proxy layer. |
| Proxy itself crashes, blocking agent workflow | **Mitigated**: Failsafe mode (`failsafe.py`) detects proxy failure and can be configured to either fail-open (permit all) or fail-closed (block all). |

### E — Elevation of Privilege

| Threat | AgentWall Response |
|---|---|
| Low-trust agent delegates to high-trust agent to bypass controls | **Mitigated**: Trust Graph (`layer2/trust_graph.py`) implements the Confused Deputy defense. The weakest-link principle applies across the delegation chain. |
| Agent uses a tool to gain host OS shell access | **Mitigated**: `bash`, `python_repl`, `sql_query` are in the `EXEC_TOOLS` high-privilege set. Requires admin trust level (2) in the trust graph. |

---

## 4. Explicit Out-of-Scope Threats

The following threats are **outside AgentWall's current threat model**. Honest documentation of limitations is a sign of research maturity.

| Threat | Reason Out of Scope |
|---|---|
| **Agent-Aware Bypass**: Agent detects proxy and routes directly to `api.openai.com` | Requires TLS interception or OS-level firewall rules (eBPF/iptables). This is a deliberate design trade-off to avoid breaking IDE integrations. |
| **Prompt Injection in LLM Responses**: Malicious content in an LLM's response manipulates the next call | The proxy inspects outgoing tool calls but does not perform semantic analysis of LLM response content (addressed partially by Layer 3 semantic injection engine). |
| **Encrypted Side-Channel Exfiltration**: Agent hides data in steganographic tool call arguments | Requires deep semantic content analysis beyond syntactic pattern matching. |
| **Model Poisoning**: The underlying LLM itself has been fine-tuned to act maliciously | Out of scope for a network-layer firewall. Requires model-level provenance controls. |
| **Physical Access / Host Compromise**: Attacker has root access to the host running AgentWall | AgentWall provides no protection once the host is compromised. |
| **Zero-Day in Dependencies**: Vulnerability in FastAPI, DuckDB, or psutil | Standard software supply chain risk; mitigated by pinned versions and regular dependency updates. |

---

## 5. Security Properties Summary

| Property | Status | Mechanism |
|---|---|---|
| Audit Log Integrity | ✅ Guaranteed | HMAC-SHA256 chain |
| Attribution Non-Repudiation | ✅ Guaranteed (logged) | OS process + timestamp |
| Policy Enforcement | ✅ Enforced at boundary | Compiled YAML rules |
| Secret Exfiltration Detection | ✅ High confidence | Honeytoken 0% FPR |
| Multi-Agent Privilege Separation | ✅ Enforced | Trust Graph + RBAC |
| Proxy Bypass Detection | ❌ Not supported | Requires OS firewall |
| LLM Response Inspection | ⚠️ Partial | Layer 3 semantic engine |
