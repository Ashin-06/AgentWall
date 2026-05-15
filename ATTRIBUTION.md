# ATTRIBUTION.md — Natural Attribution Engine: Formal Specification

## Overview

The Natural Attribution Engine (NAE) is the core research contribution of AgentWall. It solves the attribution problem: *given an observed file-system modification at time T, which of the N currently active AI agents caused it?* — without requiring TLS interception, agent-side instrumentation, or OS kernel hooks.

This document provides a precise algorithmic description suitable for a thesis methods section.

---

## Problem Formulation

Let **A = {a₁, a₂, ..., aₙ}** be the set of AI agent processes currently running on the host system.

Let **E** be a file-system event (modification, creation, deletion) at timestamp **T** on path **P**.

The attribution function **f(E, A) → aᵢ** outputs the most likely agent responsible for **E**.

---

## Algorithm: Multi-Signal Attribution (MSA)

The NAE uses a three-phase weighted voting approach:

```
Algorithm: NaturalAttribution(event E, processes A)

Input:
  E: FileSystemEvent {path, timestamp T, event_type}
  A: List of ProcessSnapshot {pid, name, cmdline, open_files, create_time, cpu_recent}

Output:
  attribution: AgentID (string)
  confidence: float [0.0, 1.0]

Phase 1 — Candidate Filtering:
  candidates ← []
  for each process p in A:
    if p.name ∈ KNOWN_AGENT_SIGNATURES or p.cmdline ∩ KNOWN_CLI_AGENTS ≠ ∅:
      candidates.append(p)
  if |candidates| = 0:
    return ("system_sentinel", 0.0)   // no known agent found

Phase 2 — Signal Scoring:
  scores ← {}
  for each candidate p in candidates:
    score ← 0.0

    // Signal 1: Open File Handle (weight=1.0 — strongest signal)
    if E.path ∈ p.open_files:
      score += 1.0

    // Signal 2: Recent CPU activity within correlation window W (weight=0.6)
    if p.cpu_recent_ms > CPU_THRESHOLD and (T - p.last_active_ts) < W:
      score += 0.6

    // Signal 3: Process name signature match (weight=0.3 — baseline prior)
    if p.name ∈ KNOWN_AGENT_SIGNATURES:
      score += 0.3

    // Signal 4: Child process of known agent launcher (weight=0.4)
    if p.parent_name ∈ LAUNCHER_SIGNATURES:
      score += 0.4

    scores[p.pid] ← score

Phase 3 — Conflict Resolution:
  if all scores are equal (tie):
    // Tiebreaker 1: Most recently active process wins
    winner ← argmax(p.last_active_ts for p in candidates)
  else:
    winner ← argmax(scores)

  confidence ← scores[winner] / MAX_POSSIBLE_SCORE   // normalize [0,1]
  return (AGENT_LABEL[winner.name], confidence)
```

---

## Key Parameters

| Parameter | Default Value | Description |
|---|---|---|
| `W` (correlation window) | 2.0 seconds | Time window between file event and agent activity |
| `CPU_THRESHOLD` | 5% | Minimum CPU usage to be considered "active" |
| `MAX_POSSIBLE_SCORE` | 2.3 | Sum of all signal weights (normalization constant) |

---

## Signal Priority and Rationale

| Signal | Weight | Rationale |
|---|---|---|
| Open File Handle | 1.0 | OS-verified: process has the file open — strongest possible signal |
| CPU Activity | 0.6 | Agent actively computing implies recent write activity |
| Process Name Match | 0.3 | Heuristic prior — known agents are more likely |
| Parent Process | 0.4 | Extension hosts (e.g., VS Code extension host) inherit parent identity |

---

## Conflict Resolution Policy

When two agents have identical attribution scores (a tie), the system resolves ambiguity using a strict priority order:

1. **Open File Handle** — if one candidate has E.path in its open file descriptors, it wins unconditionally.
2. **Last Active Timestamp** — the process with the most recent CPU burst wins.
3. **Process Creation Time (Recency)** — the most recently started process wins (assumes active session).
4. **Lexicographic Fallback** — deterministic ordering by PID prevents non-determinism.

In high-concurrency environments (N ≥ 3 concurrent agents), a "contested" flag is raised and the event is logged with `attribution_confidence < 0.4`, signalling to analysts that manual review is required.

---

## False Attribution Scenarios (Known Limitations)

| Scenario | Effect | Mitigation |
|---|---|---|
| Two agents modify the same file within W | Ambiguous attribution | `contested` flag set; both agents recorded |
| Agent uses async/deferred writes | Event timestamp shifted | Extended window W; write queue correlation |
| Non-AI process (e.g., antivirus) touches file | False attribution | Blocklist of known non-agent system processes |
| Agent process spawns subprocess for writes | Parent-child split | Parent process chain traversal (Signal 4) |

---

## Implementation Reference

The implementation of this algorithm lives in `agentwall/audit/system_watcher.py` (`get_likely_agent()` function) and is integrated into the `SystemAuditHandler` class which is invoked by `watchdog` on every file-system modification event.

---

## Experimental Validation

The attribution accuracy of the NAE was evaluated in a controlled multi-agent environment. See `evals/attribution_accuracy.py` for the full experimental setup and `evals/run_benchmarks.py` for the performance latency results.

**Key Result**: In a single-agent environment, NAE achieves 100% attribution accuracy. In a dual-agent concurrent environment with non-overlapping file paths, accuracy remains 100%. In the adversarial case (two agents writing to the same file within the correlation window W), the `contested` flag is raised correctly.
