import os
import time
import uuid
import asyncio
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import psutil

def get_likely_agent():
    """Heuristic to find which AI IDE or Agent is currently active."""
    try:
        # Common AI process signatures
        for proc in psutil.process_iter(['name', 'cmdline']):
            name = (proc.info['name'] or "").lower()
            cmd  = " ".join(proc.info['cmdline'] or []).lower()
            
            if "code.exe" in name or "vscode" in name: return "VS_Code_Copilot"
            if "cursor" in name: return "Cursor_AI"
            if "windsurf" in name: return "Windsurf_AI"
            if "pycharm" in name: return "PyCharm_AIAssistant"
            if "idea" in name: return "IntelliJ_AI"
            
            # CLI Agents
            if "aider" in cmd: return "Aider_CLI"
            if "opendevin" in cmd: return "OpenDevin"
            if "gpt-engineer" in cmd: return "GPT_Engineer"
            if "interpreter" in cmd: return "OpenInterpreter"
    except:
        pass
    return "system_sentinel"

class SystemAuditHandler(FileSystemEventHandler):
    def __init__(self, loop):
        self.loop = loop
        self._last_trigger = {} # Throttling

    def on_modified(self, event):
        if event.is_directory: return
        filename = os.path.basename(event.src_path)
        if any(x in filename for x in [".duckdb", ".wal", ".log", ".pyc", "__pycache__", ".tmp", "audit_spillover"]): 
            return
        
        now = time.time()
        if now - self._last_trigger.get(event.src_path, 0) < 1: # Higher sensitivity
            return
        self._last_trigger[event.src_path] = now

        from agentwall.audit.write_queue import DBWriteQueue
        rel_path = os.path.relpath(event.src_path, os.getcwd())
        
        # NATURAL ATTRIBUTION (Issue 15)
        agent_id = get_likely_agent()
        
        event_row = (
            "SYSTEM_WATCH", agent_id, str(uuid.uuid4()), "file_modify",
            {"path": rel_path, "process": agent_id}, "AUDIT", 
            f"Natural Observation: File modified by {agent_id}", 
            {"type": "fs_watch"}, "T1078", "system", 0.1, False, "system"
        )
        
        try:
            asyncio.run_coroutine_threadsafe(
                DBWriteQueue.get().write(event_row),
                self.loop
            )
        except Exception as e:
            pass

def start_system_watcher(loop):
    print("[Audit] [INIT] Starting Automatic System Sentinel (FS Watch)...")
    observer = Observer()
    observer.schedule(SystemAuditHandler(loop), path=".", recursive=True)
    observer.start()
    return observer
