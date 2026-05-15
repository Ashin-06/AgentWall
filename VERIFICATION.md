# ✅ Verification Guide

Use these step-by-step proofs to verify that AgentWall is correctly protecting your environment.

## Proof 1: Natural File Observation
This proof demonstrates AgentWall's ability to attribute file-system changes to specific AI processes without any configuration.

1. **Start AgentWall**: Run `run_native.bat`.
2. **Open Dashboard**: Go to `http://localhost:8000`.
3. **Trigger Event**: Open VS Code, Cursor, or Windsurf. Create a new file or save an existing one.
4. **Verification**: Look at the "Live Violations" or "Sessions" feed on the dashboard. You should see a `file_modify` event with the IDE name (e.g., `VS_Code_Copilot`) automatically tagged.

---

## Proof 2: Gateway Interception
This proof demonstrates the Universal Gateway's ability to log "Thoughts" (LLM calls).

1. **Configure Agent**: Point any AI tool to the AgentWall gateway:
   - Base URL: `http://localhost:8000/v1`
2. **Perform Action**: Ask the agent to perform a task (e.g., "Explain how this code works").
3. **Verification**: Navigate to the **Session Replay** tab on the dashboard. You will see the full prompt, the agent's internal reasoning, and the final response logged in the forensic feed.

---

## Proof 3: Policy Enforcement (Blocking)
This proof demonstrates the active defense capabilities.

1. **Enable Enforcement**: In `config/policy.yaml`, set `mode: enforced`.
2. **Restart AgentWall**: Restart the server.
3. **Trigger Violation**: Use an agent to attempt a "forbidden" action (e.g., trying to read a sensitive system path defined in the rules).
4. **Verification**: The agent's request will be intercepted and returned with a **403 Forbidden** error. The dashboard will pulse red and log a **BLOCK** event with the corresponding MITRE technique.
