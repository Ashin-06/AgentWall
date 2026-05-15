"""
Natural Attribution Engine (NAE) — System Watcher
===================================================
Implements the Multi-Signal Attribution (MSA) Algorithm described in ATTRIBUTION.md.

This module monitors the host filesystem for modifications and attributes each event
to the most likely active AI agent process using weighted signal scoring.

Attribution signals (in descending priority):
  1. Open File Handle  (weight=1.0)  — strongest: OS-verified file descriptor
  2. CPU Activity      (weight=0.6)  — agent actively computing within window W
  3. Process Name      (weight=0.3)  — known agent signature match
  4. Parent Process    (weight=0.4)  — extension host parent chain

Conflict Resolution:
  - If multiple agents tie in score, the most recently active process wins.
  - A 'contested' flag is set when confidence < 0.4 (ambiguous environment).
"""

import os
import time
import uuid
import asyncio
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ── Known Agent Signatures ─────────────────────────────────────────────────────

KNOWN_AGENTS = {
    "code.exe":   "VS_Code_Copilot",
    "code":       "VS_Code_Copilot",
    "vscode":     "VS_Code_Copilot",
    "cursor":     "Cursor_AI",
    "windsurf":   "Windsurf_AI",
    "pycharm":    "PyCharm_AIAssistant",
    "idea":       "IntelliJ_AI",
}

KNOWN_CLI_AGENTS = {
    "aider":          "Aider_CLI",
    "opendevin":      "OpenDevin",
    "gpt-engineer":   "GPT_Engineer",
    "interpreter":    "OpenInterpreter",
}

LAUNCHER_PARENTS = {"code.exe", "code", "cursor", "windsurf"}

# MSA Algorithm Parameters
# W: a process is considered "recently active" if it had non-trivial CPU usage
# at the moment of the snapshot (psutil does not expose per-second history,
# so we use the snapshot cpu_percent as the best available proxy).
CORRELATION_WINDOW_S = 2.0    # Reserved for future per-second history tracking
CPU_THRESHOLD_PCT    = 5.0    # Minimum CPU% to be considered active
SIGNAL_WEIGHTS = {
    "open_file_handle": 1.0,
    "cpu_activity":     0.6,
    "name_match":       0.3,
    "parent_match":     0.4,
}
MAX_SCORE = sum(SIGNAL_WEIGHTS.values())  # 2.3 — normalization constant


# ── MSA Implementation ─────────────────────────────────────────────────────────

def _get_process_snapshot() -> list[dict]:
    """Capture current process table for attribution scoring."""
    snapshot = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'open_files', 'cpu_percent', 'ppid', 'create_time']):
            try:
                info = proc.info
                name = (info['name'] or "").lower()
                cmd  = " ".join(info['cmdline'] or []).lower()
                open_paths = set()
                try:
                    open_paths = {f.path for f in (info['open_files'] or [])}
                except (psutil.AccessDenied, TypeError):
                    pass
                snapshot.append({
                    "pid":         info['pid'],
                    "name":        name,
                    "cmdline":     cmd,
                    "open_files":  open_paths,
                    "cpu_pct":     info['cpu_percent'] or 0.0,
                    "ppid":        info['ppid'],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return snapshot


def _score_process(proc: dict, event_path: str, event_ts: float) -> float:
    """
    Phase 2 of MSA: compute weighted signal score for one candidate process.

    Note on Signal 2 (CPU Activity):
    psutil.cpu_percent() returns the CPU usage since the last call, which
    is the best available proxy for "was this process active recently" without
    OS-level per-second CPU history. CORRELATION_WINDOW_S is the intended
    semantic but is approximated via the cpu_percent snapshot threshold.
    """
    score = 0.0

    # Signal 1: Open file handle (strongest — OS-verified)
    if event_path in proc["open_files"]:
        score += SIGNAL_WEIGHTS["open_file_handle"]

    # Signal 2: CPU activity (proxy for "active within correlation window")
    # Best approximation available without kernel-level per-second history.
    if proc["cpu_pct"] >= CPU_THRESHOLD_PCT:
        score += SIGNAL_WEIGHTS["cpu_activity"]

    # Signal 3: Process name is a known AI agent signature
    if proc["name"] in KNOWN_AGENTS:
        score += SIGNAL_WEIGHTS["name_match"]

    # Signal 4: Parent process is a known IDE launcher
    # Extension hosts (e.g. VS Code extension host) inherit the IDE's identity.
    if proc.get("ppid"):
        try:
            parent = psutil.Process(proc["ppid"])
            if parent.name().lower() in LAUNCHER_PARENTS:
                score += SIGNAL_WEIGHTS["parent_match"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return score


def attribute_event(event_path: str, event_ts: float) -> dict:
    """
    Main attribution function — implements all three phases of the MSA algorithm.

    Returns:
        dict: {
            "agent_id": str,         — attributed agent label
            "confidence": float,     — normalized [0, 1]
            "contested": bool,       — True when multiple agents tie
            "pid": int | None
        }
    """
    snapshot = _get_process_snapshot()

    # Phase 1: Candidate filtering
    candidates = []
    for proc in snapshot:
        if proc["name"] in KNOWN_AGENTS:
            candidates.append((proc, KNOWN_AGENTS[proc["name"]]))
        else:
            for sig, label in KNOWN_CLI_AGENTS.items():
                if sig in proc["cmdline"]:
                    candidates.append((proc, label))
                    break

    if not candidates:
        return {"agent_id": "system_sentinel", "confidence": 0.0, "contested": False, "pid": None}

    # Phase 2: Signal scoring
    scores = {}
    labels = {}
    for proc, label in candidates:
        pid = proc["pid"]
        scores[pid] = _score_process(proc, event_path, event_ts)
        labels[pid] = label

    # Phase 3 — Conflict Resolution
    max_score = max(scores.values())
    top_pids  = [pid for pid, s in scores.items() if s == max_score]
    contested = len(top_pids) > 1
    if contested:
        # Tiebreaker: among tied candidates, the one with highest CPU usage
        # is most likely the active writer. Build a lookup from pid -> proc.
        pid_to_proc = {proc["pid"]: proc for proc, _ in candidates}
        winner_pid = max(top_pids, key=lambda p: pid_to_proc.get(p, {}).get("cpu_pct", 0.0))
    else:
        winner_pid = top_pids[0]

    confidence = max_score / MAX_SCORE if MAX_SCORE > 0 else 0.0

    return {
        "agent_id":   labels[winner_pid],
        "confidence": round(confidence, 4),
        "contested":  contested or confidence < 0.4,
        "pid":        winner_pid,
    }


def get_likely_agent() -> str:
    """
    Legacy wrapper: returns only the agent_id string.
    Preserved for backward compatibility with existing call sites.
    """
    result = attribute_event("", time.time())
    return result["agent_id"]


# ── Watchdog Integration ───────────────────────────────────────────────────────

class SystemAuditHandler(FileSystemEventHandler):
    """
    Watchdog handler that fires on filesystem modifications and feeds them
    through the NAE attribution pipeline.
    """

    # Filename patterns to ignore (internal AgentWall files)
    IGNORE_PATTERNS = frozenset([
        ".duckdb", ".wal", ".log", ".pyc", "__pycache__", ".tmp", "audit_spillover"
    ])

    def __init__(self, loop):
        self.loop = loop
        self._last_trigger = {}  # Debounce map: path → last_ts

    def on_modified(self, event):
        if event.is_directory:
            return
        filename = os.path.basename(event.src_path)
        if any(x in filename for x in self.IGNORE_PATTERNS):
            return

        # Debounce: ignore events within 1 second of the last event on the same path
        now = time.time()
        if now - self._last_trigger.get(event.src_path, 0) < 1.0:
            return
        self._last_trigger[event.src_path] = now

        from agentwall.audit.write_queue import DBWriteQueue
        rel_path = os.path.relpath(event.src_path, os.getcwd())

        # MSA Attribution
        attribution = attribute_event(event.src_path, now)
        agent_id    = attribution["agent_id"]
        confidence  = attribution["confidence"]
        contested   = attribution["contested"]

        event_row = (
            "SYSTEM_WATCH", agent_id, str(uuid.uuid4()), "file_modify",
            {"path": rel_path, "process": agent_id,
             "attribution_confidence": confidence,
             "contested": contested},
            "AUDIT",
            f"Natural Observation: File modified by {agent_id} "
            f"(confidence={confidence:.2f}{'[CONTESTED]' if contested else ''})",
            {"type": "fs_watch", "attribution": attribution},
            "T1078", "system", 0.1, False, "system"
        )

        try:
            asyncio.run_coroutine_threadsafe(
                DBWriteQueue.get().write(event_row),
                self.loop
            )
        except Exception:
            pass


def start_system_watcher(loop):
    """Start the watchdog filesystem observer on the current working directory."""
    print("[Audit] [INIT] Starting Natural Attribution Engine (Filesystem Watch)...")
    observer = Observer()
    observer.schedule(SystemAuditHandler(loop), path=".", recursive=True)
    observer.start()
    return observer
