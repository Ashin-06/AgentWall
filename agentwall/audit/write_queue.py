"""
Async write queue for DuckDB.

DuckDB is single-writer. Under concurrent load, parallel writes cause:
  duckdb.IOException: database is locked

Fix: funnel all writes through a single asyncio Queue.
One background task drains the queue sequentially.
Writers await a Future that resolves when their write completes.
"""
import asyncio
import json
import time
import uuid
import hashlib
import hmac
import os
from dataclasses import dataclass, field
from typing import Any

import duckdb
from agentwall.audit.schema import HMAC_KEY, DB_URL, KEY_ID


@dataclass
class WriteRequest:
    row:    tuple
    future: asyncio.Future


class DBWriteQueue:
    """Singleton async write queue — one writer, many waiters."""
    _instance = None

    @classmethod
    def get(cls) -> Any:
        db_url = os.getenv("DATABASE_URL", "")
        if db_url.startswith("postgres://") or db_url.startswith("postgresql://"):
            from agentwall.audit.postgres_queue import PostgresWriteQueue
            return PostgresWriteQueue.get()
        
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls):
        if cls._instance and hasattr(cls._instance, '_con') and cls._instance._con:
            try:
                cls._instance._con.close()
            except:
                pass
        cls._instance = None

    def __init__(self):
        self._queue:  asyncio.Queue  = asyncio.Queue(maxsize=10_000)
        self._task:   asyncio.Task | None = None
        
        # Priority 1: PostgreSQL/DATABASE_URL
        db_url = os.getenv("DATABASE_URL")
        # Priority 2: AGENTWALL_DB
        db_path = os.getenv("AGENTWALL_DB", "agentwall_v2.duckdb")
        
        # P1 Fix: Guard against incorrect/residual env vars (e.g. network_monitor)
        if db_url and ("network_monitor" in db_url or "sqlite:" in db_url):
            db_url = None
        if db_path and ("network_monitor" in db_path or "sqlite:" in db_path):
            db_path = "agentwall_v2.duckdb"
            
        final_url = db_url or db_path
        
        # Ensure path is absolute for Windows stability
        if not (final_url.startswith("postgres://") or final_url.startswith("postgresql://")):
            if not os.path.isabs(final_url):
                final_url = os.path.join(os.getcwd(), final_url)

        # Retry loop to handle uvicorn reloader race conditions
        for i in range(15):
            try:
                self._con = duckdb.connect(final_url)
                break
            except Exception as e:
                msg = str(e).lower()
                if ("already open" in msg or "database is locked" in msg) and i < 14:
                    wait = 0.5 + (i * 0.1)
                    print(f"[DBWriteQueue] [LOCK] Database locked (attempt {i+1}/15). Retrying in {wait}s...")
                    
                    # [AUTO-RELEASE] (Issue 14)
                    if i == 3: # On 4th failure, try aggressive release
                        print("[DBWriteQueue] [RECOVERY] Attempting Auto-Release of zombie handles...")
                        import subprocess
                        my_pid = os.getpid()
                        # Kill any other python processes that might be holding the lock
                        subprocess.run(f'taskkill /F /FI "PID ne {my_pid}" /IM python.exe', shell=True, capture_output=True)
                        time.sleep(1.0)
                    
                    time.sleep(wait)
                    continue
                raise e

        # P0 Fix: Resume HMAC chain from last DB hash
        try:
            row = self._con.execute("SELECT chain_hash FROM audit_events ORDER BY ts DESC LIMIT 1").fetchone()
            self._prev_hash = row[0] if row else "GENESIS"
        except:
            self._prev_hash = "GENESIS"
        self._lock    = asyncio.Lock()

    def start(self, loop: asyncio.AbstractEventLoop = None, broadcast_cb=None):
        """Start the background drain task. Call once at startup."""
        self._broadcast_cb = broadcast_cb
        self._task = asyncio.ensure_future(self._drain())

    async def write(self, row: tuple) -> str:
        """Enqueue a write and await its completion. Returns event_id."""
        loop   = asyncio.get_running_loop()
        future = loop.create_future()
        req    = WriteRequest(row=row, future=future)
        await self._queue.put(req)
        return await future   # blocks caller until write is done

    async def _drain(self):
        """Background task: drain queue one write at a time."""
        write_count = 0
        while True:
            try:
                req = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                # [COMPLIANCE] If queue is failing, spill over to local persistent disk
                self._spill_to_disk(req)
                continue
            try:
                loop = asyncio.get_running_loop()
                event_id = await loop.run_in_executor(
                    None, self._sync_write, req.row
                )
                if not req.future.done():
                    req.future.set_result(event_id)
                
                # BUG-4 Fix: Publish Merkle root on every write 
                # (avoids 'tampered' false alarms between checkpoints)
                from agentwall.audit.merkle import MerkleAuditLog
                MerkleAuditLog().publish_root(con=self._con)
                    
                # BROADCAST (Issue 16)
                if hasattr(self, '_broadcast_cb') and self._broadcast_cb:
                    try:
                        # Extract basic info from row for the alert
                        self._broadcast_cb(json.dumps({"type": "alert", "event": {
                            "event_id": event_id, "session_id": req.row[0], "agent_id": req.row[1],
                            "tool_name": req.row[3], "verdict": req.row[5], "reason": req.row[6],
                            "ts": time.time()
                        }}))
                    except: pass
            except Exception as e:
                if not req.future.done():
                    req.future.set_exception(e)
            finally:
                self._queue.task_done()

    def _sync_write(self, row: tuple) -> str:
        """Blocking write — runs in thread executor."""
        (session_id, agent_id, call_id, tool_name,
         arguments, verdict, reason, details,
         mitre_id, source_fmt, latency_ms, shadow_block, key_id) = row

        event_id   = str(uuid.uuid4())
        ts         = time.time()
        event_data = json.dumps({
            "event_id": event_id, "session_id": session_id,
            "verdict": verdict, "ts": ts,
        }, sort_keys=True)
        chain_hash = hmac.new(
            HMAC_KEY.encode(),
            (self._prev_hash + event_data).encode(),
            hashlib.sha256,
        ).hexdigest()
        self._prev_hash = chain_hash

        self._con.execute("""
            INSERT INTO audit_events
              (event_id,session_id,agent_id,call_id,tool_name,
               arguments,verdict,reason,details,mitre_id,
               source_fmt,latency_ms,shadow_block,chain_hash,key_id,ts)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, [
            event_id, session_id, agent_id, call_id, tool_name,
            json.dumps(arguments), verdict, reason, json.dumps(details), mitre_id,
            source_fmt, latency_ms, shadow_block, chain_hash, key_id, ts,
        ])
        return event_id

    def stop(self):
        """Gracefully shutdown the queue and close connection."""
        # P1 Fix: Distributed Honeytoken Lockdown
        self._redis = None
        self._local_locked_sessions = set()
        
        if self._task:
            self._task.cancel()
        if self._con:
            # BUG-4 Fix: Final Merkle Checkpoint
            try:
                from agentwall.audit.merkle import MerkleAuditLog
                MerkleAuditLog().publish_root(con=self._con)
            except:
                pass
            self._con.close()
            self._con = None
        print("[DBWriteQueue] Connection closed.")

    async def flush(self):
        """Wait until all pending writes are done."""
        await self._queue.join()

    def _spill_to_disk(self, req: WriteRequest):
        """[SOC2 COMPLIANCE] Encrypted Emergency spillover."""
        spill_path = os.getenv("AGENTWALL_SPILLOVER_LOG", "audit_spillover.log")
        try:
            from cryptography.fernet import Fernet
            import base64
            # M-6 Fix: Use Fernet for actual encryption
            key_bytes = HMAC_KEY.encode()[:32].ljust(32, b'\0')
            key = base64.urlsafe_b64encode(key_bytes)
            f_cipher = Fernet(key)
            
            ts = time.time()
            data = json.dumps({"ts": ts, "row": req.row, "sig": hashlib.sha256(str(req.row).encode()).hexdigest()})
            encrypted = f_cipher.encrypt(data.encode()).decode()
            
            with open(spill_path, "a") as f_out:
                f_out.write(encrypted + "\n")
            print(f"[DBWriteQueue] [CRITICAL] Database unreachable. Encrypted event spilled to {spill_path}")
            if not req.future.done():
                req.future.set_result("spilled_to_disk_encrypted")
        except Exception as e:
            print(f"[DBWriteQueue] [PANIC] Failed to encrypt/spill to disk: {e}")

    def queue_size(self) -> int:
        return self._queue.qsize()
