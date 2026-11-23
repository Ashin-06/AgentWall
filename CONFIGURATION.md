#  Configuration Guide

> [!CAUTION]
> **CRITICAL SECURITY WARNING**: The default administrator password is `admin`. This MUST be changed in your `.env` file before any live deployment.

AgentWall configuration is handled via environment variables and a policy file.

## 1. Environment Variables (.env)
Copy `.env.example` to `.env` to customize settings:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AGENTWALL_ADMIN_PASSWORD` | Password for the SOC Dashboard | random, printed at startup |
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

## 4. Production Deployment

By default, the AgentWall development server runs with a single worker. If that worker crashes, the proxy goes down and takes your agents offline with it.

For production, it is highly recommended to use `gunicorn` with `uvicorn` workers to ensure high availability and automatic restarts:

```bash
gunicorn agentwall.main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

## Human approval (HITL)

Calls to high-risk tools (`delete_db`, `send_payment`, `drop_table`, `sudo_command`, matched as
substrings of the tool name) that pass every other layer are held: the verdict is `BLOCK` and
`details.hitl.token` carries an approval token.

1. An admin lists held calls with `GET /api/hitl/pending` and decides with
   `POST /api/hitl/{token}/approve` or `POST /api/hitl/{token}/deny`. These endpoints need the
   dashboard login (admin JWT); an agent API key gets 403.
2. The agent resends the same call with the header `X-AgentWall-Approval-Token: <token>`.

The token only unlocks the exact call it was issued for (same session, agent, tool and
arguments), works once, and expires after `AGENTWALL_HITL_TTL` seconds (default 3600). Tokens are
kept in Redis when `REDIS_URL` is set, otherwise in process memory (lost on restart).
## Metrics and live alerts

- `/metrics` (Prometheus) requires auth like the rest of the API: send one of `AGENTWALL_API_KEYS`
  as `Authorization: Bearer <key>` or `X-AgentWall-Key`. `config/prometheus.yml` reads it from a
  credentials file.
- The live-alert WebSocket (`/ws/intercept`) expects `{"type": "auth", "token": "<jwt or api key>"}`
  as its first message within 5 seconds, so tokens never appear in URLs or access logs. With
  `AGENTWALL_AUTH_ENABLED=0` no auth message is needed.
