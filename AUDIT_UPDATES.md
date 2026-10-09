# Audit and maintenance update — 2026-10-09

This pass preserves the existing README, product copy, branding, six dashboard tabs, and forensic export. It focuses on dashboard reliability, database recovery, and regression coverage. It is not a complete security certification.

## Fixed

- Failed dashboard requests no longer silently replace existing data with empty arrays. A visible error retains the last successful snapshot, and expired REST authentication returns to sign-in.
- Refresh and session replay requests are cancelled when superseded or closed. Switching sessions resets replay selection; replay failures have a retry control.
- Metrics uses the shared WebSocket client, reads the server's `{type: "alert", event: ...}` envelope, and stops reconnecting after unmount.
- Metric cards display actual values without random jitter. Alert timestamps come from events; chart zoom stays within usable bounds.
- Added the previously missing authenticated `/api/performance` endpoint. P50/P95/P99 use nearest-rank percentiles of retained in-process latency observations, converted to milliseconds. No observations returns zero with `sample_count: 0`; historical database events do not populate these latency samples.
- Removed database-lock recovery that terminated other Python processes. Exhausted retries now report the lock failure.
- Audit chain state advances only after a successful insert, preserving the previous hash on failed writes.
- Explicit environment variables take precedence over `.env` values.
- Sessions and violations reject limits outside 1–1000.

## Added

- Session search by agent or session ID, combined with the agent filter.
- Manual refresh, overview polling pause/resume, last-update time, and sign-out with state cleanup. Live alerts and Metrics polling continue while overview polling is paused.
- Responsive overview/metrics layouts, keyboard access to session rows, visible keyboard focus for controls, and reduced-motion support.
- Backend regression tests and dashboard client tests (`npm test` in `dashboard`). Test clients disable the OS filesystem watcher and use isolated in-memory queues.

## Validation

- Production dashboard build succeeds. The first attempt encountered a Windows sandbox directory-access restriction; the same build succeeded with the required access.
- 39 backend tests passed after the second audit pass.
- 3 dashboard client regression tests passed.
- No live LLM integration, production traffic benchmark, browser visual verification, or dependency vulnerability scan was performed in this pass.

## Remaining findings

These pre-existing issues require a separate security-focused implementation and integration validation:

- The universal gateway now requires authentication and records requests as AUDIT, but still does not execute the detection pipeline. The dashboard explicitly labels it monitoring-only; use the authenticated tool-call adapters for policy checks. Provider forwarding and streaming need further integration work.
- Default dashboard password remains `admin` outside production for compatibility. Production startup now rejects missing, weak, or example secrets. Login throttling and deployment-wide credential rotation remain future work.
- `agentwall/audit/write_queue.py`: the HMAC input covers event ID, verdict, and timestamp, rather than every stored event field. The chain-state fix does not establish full-record tamper protection.
- Prometheus rendering currently omits histogram series, though the new performance endpoint reads the recorded latency observations directly.

Publication status is reported in the accompanying Git commit and GitHub Actions run. No production deployment is included.

## Second audit pass

- Fixed shadow mode overriding BLOCK even when disabled. Explicit shadow mode still returns a would-block result; enforcement mode preserves BLOCK.
- Fixed lazy injection detector initialization and missing reasoning in heuristic results.
- Connected the graph endpoint to the causal detector and fixed node-ID collisions after graph retention reaches 200 calls.
- Added an authenticated security-status endpoint and a dashboard indicator for enforcement/observation, authentication, profile, and the monitoring-only gateway.
- Protected interception, output sanitization, and gateway routes with the existing authentication dependency.
- Restored native adapter normalization and `/intercept/langchain`, and exposed the existing sanitizer through `/intercept/output`.
- Updated adapter transport to send `AGENTWALL_API_KEY` and raise an authorization error on HTTP/network failures before a tool runs. Framework-specific output callbacks still have legacy exception handling; full SDK integration tests were not run.
- Replaced the predictable fallback JWT signing secret with an ephemeral random secret and removed the implicit development API key. JWTs must include expiration, issued-at, and subject claims.
- Moved production secret validation from unreachable proxy code into startup. Login now returns the configured token lifetime.

### Integration update

Configure `AGENTWALL_API_KEYS` on the server with private keys. Set `AGENTWALL_API_KEY` in each adapter process to one matching key. Direct clients must send `X-AgentWall-Key` (or a dashboard Bearer JWT) to protected endpoints; an upstream provider API key is not an AgentWall credential.

## Pre-push verification

- 41 backend tests and 3 dashboard client tests pass; the production dashboard builds.
- Attribution simulation passes its three accuracy/conflict scenarios. This is still an algorithm simulation, not live-process attribution validation.
- The Layer 1 benchmark now runs with enforcement enabled, checks HTTP failures, and isolates RBAC, campaign state, Redis, and the filesystem watcher. It blocks all 25 malicious samples. Six of the 25 non-malicious fixtures are deliberately denied by the shipped policy (relative writes and code execution); it reports the 24% raw benign block rate separately from the 0% unexpected-block rate. The previous zero-FPR claim was masked by shadow mode and should not be interpreted as an enforcement result. Policies and datasets are unchanged.
- Added `/health` for container health checks, a dashboard build stage in the Docker image, a Docker context exclusion file, and dashboard checks in GitHub Actions.
- Campaign detection verifies Redis connectivity and falls back to local state if Redis fails during initialization or ingestion.
- Local Docker verification was unavailable because the daemon was not running; GitHub Actions performs the container build.

For the OpenAI SDK gateway, add `default_headers={"X-AgentWall-Key": "YOUR_AGENTWALL_KEY"}` to the client options. Gateway traffic remains monitoring-only. Use `AGENTWALL_SHADOW_MODE=0` for tool-call enforcement, or `1` explicitly for observation. In production, set `AGENTWALL_ENV=production` with private JWT/HMAC secrets of at least 32 characters and an admin password of at least 16 characters. Configured API keys must be at least 32 characters. Missing JWT configuration outside production uses a random per-process secret, invalidating sessions on restart.
