# COMPARISON.md — AgentWall vs. Related Work

## Context

This document positions AgentWall relative to existing tools and frameworks in the AI agent security space. A key component of any MTech thesis is a formal comparison against baselines.

---

## 1. Comparison Table

| Feature / Dimension | **AgentWall** | **LiteLLM Proxy** | **Guardrails-AI** | **OWASP LLM Top 10 Mitigations** |
|---|---|---|---|---|
| **Primary Purpose** | AI Agent Security Firewall | LLM API Load Balancing & Cost Control | LLM Output Validation | Security Guidelines (not a tool) |
| **Deployment Model** | Sidecar Proxy | Sidecar Proxy | In-process Library | Documentation |
| **Protocol Support** | OpenAI, Anthropic, Gemini | 100+ LLM providers | LLM-agnostic | N/A |
| **Process Attribution** | ✅ OS-level (psutil/watchdog) | ❌ Not provided | ❌ Not provided | ❌ Not provided |
| **Policy Enforcement (Tool Calls)** | ✅ YAML rule engine | ❌ Not provided | ⚠️ Output guardrails only | ⚠️ Recommended practice |
| **Tamper-Evident Audit Log** | ✅ HMAC-chained DuckDB | ⚠️ Request logs only | ❌ Not provided | ❌ Not provided |
| **Honeytoken Active Defense** | ✅ Built-in | ❌ Not provided | ❌ Not provided | ✅ Recommended (LLM07) |
| **MITRE ATT&CK Mapping** | ✅ Automated per-event | ❌ Not provided | ❌ Not provided | ⚠️ Framework reference only |
| **Multi-Agent Trust Graph** | ✅ Confusion-deputy defense | ❌ Not provided | ❌ Not provided | ❌ Not provided |
| **Prompt Injection Detection** | ✅ Layer 3 Semantic Engine | ❌ Not provided | ✅ Output validation | ✅ Recommended (LLM01) |
| **Real-Time SOC Dashboard** | ✅ React + Session Replay | ⚠️ Basic UI | ❌ Not provided | ❌ Not provided |
| **Anomaly Detection** | ✅ Isolation Forest ensemble | ❌ Not provided | ❌ Not provided | ❌ Not provided |
| **Rate Limiting** | ✅ Per-agent | ✅ Per-model | ❌ Not provided | ❌ Not provided |
| **RBAC** | ✅ Agent-level RBAC | ⚠️ Team-level | ❌ Not provided | ❌ Not provided |
| **Horizontal Scaling** | ✅ Redis-backed state | ✅ Native | ⚠️ Stateless | N/A |
| **Zero Config Attribution** | ✅ No agent modification needed | ❌ Agent must set base_url | ❌ Requires code instrumentation | N/A |
| **Open Source** | ✅ MIT License | ✅ MIT License | ✅ Apache 2.0 | ✅ CC License |

---

## 2. Detailed Comparison

### 2a. vs. LiteLLM Proxy

**LiteLLM** ([github.com/BerriAI/litellm](https://github.com/BerriAI/litellm)) is the most widely deployed open-source LLM proxy. Its primary purpose is **cost control, load balancing, and multi-provider abstraction** — not security.

**Key Differences:**
- LiteLLM logs requests but does not perform semantic analysis or policy enforcement on tool call arguments.
- LiteLLM has no concept of agent identity or process attribution.
- LiteLLM provides no active defense mechanisms (honeytokens, MITRE mapping, etc.).
- AgentWall is not a replacement for LiteLLM — they are complementary. AgentWall can be deployed upstream of LiteLLM in a pipeline.

### 2b. vs. Guardrails-AI

**Guardrails-AI** ([github.com/guardrails-ai/guardrails](https://github.com/guardrails-ai/guardrails)) focuses on **LLM output validation** — ensuring structured outputs conform to schemas and detecting harmful content in responses.

**Key Differences:**
- Guardrails-AI operates at the LLM response level (output), while AgentWall operates at the tool call level (behavior).
- Guardrails-AI requires code instrumentation in the agent application. AgentWall is a network-level proxy requiring only `base_url` redirection.
- Guardrails-AI has no audit trail, no attribution, and no MITRE mapping.
- The threat models are complementary: Guardrails prevents LLM hallucinations; AgentWall prevents malicious tool-level actions.

### 2c. vs. OWASP LLM Top 10

**OWASP LLM Top 10** ([owasp.org/www-project-top-10-for-large-language-model-applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)) is a **risk framework**, not an implementation. It documents the 10 most critical security risks for LLM applications.

AgentWall directly implements mitigations for multiple OWASP LLM categories:

| OWASP LLM Risk | AgentWall Mitigation |
|---|---|
| **LLM01: Prompt Injection** | Layer 3 Semantic Injection Engine (LLMInjectionClassifier) |
| **LLM02: Insecure Output Handling** | Policy engine blocks dangerous tool calls spawned by LLM |
| **LLM06: Sensitive Information Disclosure** | Honeytoken defense + `/etc/passwd`, `.env` policy rules |
| **LLM07: Insecure Plugin Design** | Trust Graph confusion-deputy defense; RBAC per tool |
| **LLM08: Excessive Agency** | Rate limiter + policy engine blocks over-privileged tool calls |

---

## 3. Novelty Statement

No existing tool in the open-source ecosystem combines:
1. **OS-level process attribution** without TLS interception
2. **HMAC-chained forensic audit logs** with session replay
3. **Honeytoken active defense** specifically for AI agent traffic
4. **MITRE ATT&CK automated mapping** for agent behaviors
5. **Multi-agent trust graph** with confused-deputy prevention

This combination of primitives, applied specifically to the AI agent threat model, constitutes a novel security architecture that has not been previously published.

---

## 4. Positioning in the Literature

AgentWall occupies a unique position at the intersection of three research areas:

- **AI Safety / LLMSec**: Agent alignment and preventing unintended autonomous behavior.
- **Security Monitoring (SIEM/SOAR)**: Tamper-evident logging, MITRE mapping, SOC-style dashboards.
- **Supply Chain Security**: Attributing actions to specific tools/processes, verifying integrity.

Relevant prior work:
- *"Attacking Large Language Model Applications"* (Greshake et al., 2023) — establishes the prompt injection threat model that AgentWall's Layer 3 defends against.
- *"AgentBench"* (Liu et al., 2023) — benchmarks agent capabilities; AgentWall provides the security monitoring layer for such benchmarked agents.
- *"Honeyfiles: Honeypots for Document Management Systems"* (Bowen et al., 2009) — foundational honeytoken work adapted here for AI agent context.
