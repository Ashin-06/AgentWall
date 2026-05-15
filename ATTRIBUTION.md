# ATTRIBUTION.md — Natural Attribution Engine: Formal Specification

## Overview

The Natural Attribution Engine (NAE) is the core research contribution of AgentWall. It solves the attribution problem: *given an observed file-system modification at time T, which of the N currently active AI agent processes caused it?* — without requiring TLS interception, agent-side instrumentation, or OS kernel hooks.

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
  A: List of ProcessSnapshot {pid, name, cmdline, open_files, cpu_pct, ppid}
     (Captured via psutil at event time)

Output:
  attribution: AgentID (string)
  confidence: float [0.0, 1.0]
  contested: bool

Phase 1 — Candidate Filtering:
  candidates ← []
  for each process p in A:
    if p.name ∈ KNOWN_AGENT_SIGNATURES or p.cmdline ∩ KNOWN_CLI_AGENTS ≠ ∅:
      candidates.append(p)
  if |candidates| = 0:
    return ("system_sentinel", 0.0, False)

Phase 2 — Signal Scoring:
  scores ← {}
  for each candidate p in candidates:
    score ← 0.0

    // Signal 1: Open File Handle (weight=1.0 — strongest signal)
    // OS-verified: process holds a file descriptor for E.path
    if E.path ∈ p.open_files:
      score += 1.0

    // Signal 2: CPU Activity (weight=0.6)
    // Proxy for "active writer" — psutil exposes cpu_pct since last poll,
    // not a per-second history. This is the best available approximation
    // without kernel-level instrumentation.
    if p.cpu_pct ≥ CPU_THRESHOLD (5%):
      score += 0.6

    // Signal 3: Process name signature match (weight=0.3)
    if p.name ∈ KNOWN_AGENT_SIGNATURES:
      score += 0.3

    // Signal 4: Child process of known agent launcher (weight=0.4)
    if parent(p).name ∈ LAUNCHER_SIGNATURES:
      score += 0.4

    scores[p.pid] ← score

Phase 3 — Conflict Resolution:
  max_score ← max(scores.values())
  top_pids  ← {pid : scores[pid] == max_score}

  if |top_pids| > 1 (tie):
    // Tiebreaker: highest cpu_pct among tied candidates
    // The most CPU-active process at event time is the most likely writer.
    winner ← argmax(p.cpu_pct for p in candidates where p.pid ∈ top_pids)
    contested ← True
  else:
    winner ← top_pids[0]
    contested ← False

  confidence ← max_score / MAX_POSSIBLE_SCORE   // normalize [0, 1]
  return (AGENT_LABEL[winner.name], confidence, contested)
```

---

## Key Parameters

| Parameter | Value | Description |
|---|---|---|
| `CPU_THRESHOLD` | 5% | Minimum cpu_pct to be considered active |
| `MAX_POSSIBLE_SCORE` | 2.3 | Sum of all signal weights (normalization constant) |
| `CORRELATION_WINDOW_S` | 2.0 s | Intended window for Signal 2 — currently approximated via cpu_pct snapshot; exact windowed history requires kernel instrumentation |

---

## Signal Priority and Rationale

| Signal | Weight | Rationale |
|---|---|---|
| Open File Handle | 1.0 | OS-verified: process holds the file descriptor — strongest possible signal |
| CPU Activity | 0.6 | Active process implies recent write activity; approximated via psutil cpu_pct snapshot |
| Process Name Match | 0.3 | Heuristic prior — known agents are more likely |
| Parent Process | 0.4 | Extension hosts (e.g. VS Code extension host) inherit parent identity |

---

## Implementation Notes and Honest Limitations

### Signal 2 Approximation
The ATTRIBUTION.md algorithm describes Signal 2 as "CPU Activity within correlation window W". In the implementation (`system_watcher.py`), `psutil.cpu_percent()` returns the CPU utilization since the **last poll call** — it does not maintain a per-second history buffer. This means:
- **What is implemented**: Snapshot CPU% ≥ 5% at the time of the watchdog event
- **What the full algorithm intends**: CPU% tracked over a 2-second rolling window
- **Impact**: Slightly lower precision in multi-process environments where all processes happen to have CPU > 5% simultaneously

A future improvement would use `psutil.Process.cpu_times()` polled at 0.5s intervals to build a rolling activity buffer.

### Conflict Resolution
When two agents have identical scores, the tiebreaker picks the agent with the highest CPU% at snapshot time. This is a best-effort heuristic — in adversarial or heavily concurrent environments, a `contested=True` flag is raised, prompting human review.

---

## Experimental Validation

**Important Scope Note**: The `evals/attribution_accuracy.py` experiment validates the *MSA algorithm logic* using a deterministic simulation (`AttributionOracle`). This tests that the scoring, conflict resolution, and contested-flag logic are correct. It does **not** test the psutil I/O path or real OS process scanning latency.

### Algorithm Correctness (Simulated Oracle)

| Scenario | Accuracy | Contested Flag Rate |
|---|---|---|
| Single agent, distinct file | 100% | 0% |
| Dual agent, distinct files | 100% | 0% |
| Dual agent, same file (adversarial) | Best-effort | 100% ✅ |
| Algorithm overhead (P99) | — | 0.05 ms |

Source: `evals/attribution_accuracy.py` — simulated oracle, 50 controlled trials.

### Real-World Behavior (Qualitative)
In practice, Signal 1 (open file handle) is the dominant signal when the writing process holds the file open. On Windows, psutil's `open_files()` requires elevated permissions in some contexts; AgentWall gracefully handles `AccessDenied` and falls back to Signals 2–4.

---

## Implementation Reference

- Main implementation: `agentwall/audit/system_watcher.py` — `attribute_event()` and `_score_process()`
- Called by: `SystemAuditHandler.on_modified()` on every watchdog filesystem event
- Simulation for testing: `evals/attribution_accuracy.py` — `AttributionOracle` class
