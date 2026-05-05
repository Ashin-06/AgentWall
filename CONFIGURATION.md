# ⚙️ Configuration Guide

> [!CAUTION]
> **CRITICAL SECURITY WARNING**: The default administrator password is `admin`. This MUST be changed in your `.env` file before any live deployment.

AgentWall configuration is handled via environment variables and a policy file.

## 1. Environment Variables (.env)
Copy `.env.example` to `.env` to customize settings:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AGENTWALL_ADMIN_PASSWORD` | Password for the SOC Dashboard | `admin` |
| `AGENTWALL_UPSTREAM_KEY` | Your real AI provider API Key (OpenAI/Anthropic) | (None) |
| `AGENTWALL_UPSTREAM_URL` | Upstream routing target | `https://api.openai.com/v1/chat/completions` |
| `AGENTWALL_DB` | Path to telemetry database | `agentwall_v2.duckdb` |
| `AGENTWALL_HMAC_KEY` | Cryptographic key for log integrity | (Random) |

## 2. Security Policy (policy.yaml)
Located in `config/policy.yaml`, this file defines what actions are allowed.

### Operational Modes
- **Shadow Mode (`audit`)**: AgentWall logs everything but blocks nothing. Perfect for baselining.
- **Enforced Mode (`enforced`)**: AgentWall actively blocks tools or payloads that violate the security policy.

```yaml
mode: audit # Change to 'enforced' to enable blocking
rules:
  - id: block_system_access
    pattern: "/etc/passwd|System32"
    verdict: BLOCK
```

## 3. Connecting Your Agents
To enable LLM monitoring, update your agent configuration:

### Python (OpenAI SDK)
```python
client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="your_real_key" 
)
```

### CLI Agents (Aider / OpenDevin)
Set the environment variable before running the agent:
`export OPENAI_API_BASE=http://localhost:8000/v1`
