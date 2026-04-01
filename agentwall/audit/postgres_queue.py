"""
PostgreSQL Implementation of DBWriteQueue.
Enables production-grade, distributed audit logging.
"""
import asyncio
import json
import time
import uuid
import hashlib
import hmac
import os
import psycopg2
from psycopg2.extras import execute_values
from dataclasses import dataclass

@dataclass
class WriteRequest:
    row:    tuple
    future: asyncio.Future

class PostgresWriteQueue:
    _instance = None

    @classmethod
    def get(cls) -> "PostgresWriteQueue":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._queue:  asyncio.Queue  = asyncio.Queue(maxsize=10_000)
        self._task:   asyncio.Task | None = None
        self.db_url = os.getenv("DATABASE_URL")
        self._prev_hash = "GENESIS"
        self._hmac_key = os.getenv("AGENTWALL_HMAC_KEY", "ephemeral")

    def start(self):
        self._task = asyncio.ensure_future(self._drain())

    async def write(self, row: tuple) -> str:
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        await self._queue.put(WriteRequest(row=row, future=future))
        return await future

    async def _drain(self):
        while True:
            req = await self._queue.get()
            try:
                loop = asyncio.get_running_loop()
                event_id = await loop.run_in_executor(None, self._sync_write, req.row)
                req.future.set_result(event_id)
            except Exception as e:
                print(f"[PostgresWriteQueue] Error: {e}")
                req.future.set_exception(e)
            finally:
                self._queue.task_done()

    def _sync_write(self, row: tuple) -> str:
        conn = psycopg2.connect(self.db_url)
        try:
            with conn.cursor() as cur:
                event_id = str(uuid.uuid4())
                ts = time.time()
                # Simplified HMAC chaining for Postgres
                event_data = json.dumps({"eid": event_id, "v": row[5], "ts": ts})
                chain_hash = hmac.new(self._hmac_key.encode(), (self._prev_hash + event_data).encode(), hashlib.sha256).hexdigest()
                self._prev_hash = chain_hash

                cur.execute("""
                    INSERT INTO audit_events 
                    (event_id, session_id, agent_id, call_id, tool_name, arguments, verdict, reason, details, mitre_id, source_fmt, latency_ms, shadow_block, chain_hash, key_id, ts)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (event_id, *row[:2], row[2], row[3], json.dumps(row[4]), row[5], row[6], json.dumps(row[7]), *row[8:13], chain_hash, row[12], ts))
                conn.commit()
                return event_id
        finally:
            conn.close()
