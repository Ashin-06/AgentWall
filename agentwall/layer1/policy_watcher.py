"""
Watches policy.yaml for changes and reloads without restart.
Uses polling (no inotify dependency) — works on all OS + Docker volumes.
"""
import asyncio
import os
import time
from pathlib import Path


class PolicyWatcher:
    def __init__(self, proxy, path: str, interval: float = 5.0):
        self.proxy    = proxy
        self.path     = Path(path)
        self.interval = interval
        self._last_mtime = self._mtime()
        self._task: asyncio.Task | None = None

    def _mtime(self) -> float:
        try:
            return self.path.stat().st_mtime
        except FileNotFoundError:
            return 0.0

    def start(self):
        self._task = asyncio.ensure_future(self._watch())

    async def _watch(self):
        while True:
            await asyncio.sleep(self.interval)
            mtime = self._mtime()
            if mtime != self._last_mtime:
                try:
                    # Reload all components that depend on policy.yaml
                    self.proxy.policy.reload()
                    self.proxy.rbac.reload()
                    
                    self._last_mtime = mtime
                    print(f"[PolicyWatcher] ✅ Policy & RBAC reloaded from {self.path}")
                except Exception as e:
                    print(f"[PolicyWatcher] ❌ Reload failed: {e} (keeping previous version)")

    def stop(self):
        if self._task:
            self._task.cancel()
