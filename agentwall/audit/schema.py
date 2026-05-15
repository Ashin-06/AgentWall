"""
DuckDB schema v2.

New in v2:
  - mitre_id column on all events
  - shadow_block flag for shadow-mode observations
  - get_mitre_counts() for MITRE heatmap API
  - source_fmt column (which agent framework generated the call)
  - latency_ms stored for performance analytics
"""
import json
import os
import time
import uuid
import hashlib
import hmac
from pathlib import Path

import duckdb

import secrets
_default_key = secrets.token_hex(32)
HMAC_KEY = os.getenv("AGENTWALL_HMAC_KEY") or _default_key
if not os.getenv("AGENTWALL_HMAC_KEY"):
    print("[Audit] [WARNING] AGENTWALL_HMAC_KEY not set - using ephemeral key.")

# Enterprise Multi-Tier Persistence (Issue 1)
# Transactional: PostgreSQL (Sync) | Analytical: ClickHouse (Async)
DB_URL = os.getenv("DATABASE_URL") or os.getenv("AGENTWALL_DB", "agentwall_v2.duckdb")
# Key ID for rotation (Issue 3)
KEY_ID = os.getenv("AGENTWALL_KEY_ID", "v1-dev")

def _conn():
    # Priority 1: PostgreSQL/DATABASE_URL
    db_url = os.getenv("DATABASE_URL")
    if db_url and (db_url.startswith("postgres://") or db_url.startswith("postgresql://")):
        import psycopg2
        return psycopg2.connect(db_url)
    
    # Priority 2: Shared singleton connection from DBWriteQueue (Issue fix for Windows locking)
    print("[Schema] Accessing shared connection...")
    try:
        from agentwall.audit.write_queue import DBWriteQueue
        shared_con = DBWriteQueue.get()._con
        if shared_con:
            print("[Schema] Shared connection obtained.")
            return shared_con
    except (ImportError, AttributeError):
        print("[Schema] Shared connection not available.")
        pass

    # Priority 3: AGENTWALL_DB
    # P1 Fix: Guard against incorrect/residual env vars from other projects (e.g. network_monitor)
    db_path = os.getenv("AGENTWALL_DB", "agentwall.duckdb")
    if "network_monitor" in db_path or "sqlite:" in db_path:
        db_path = "agentwall.duckdb"
    
    # Ensure path is absolute for Windows stability
    if not os.path.isabs(db_path):
        db_path = os.path.join(os.getcwd(), db_path)
        
    return duckdb.connect(db_path)

def _get_placeholder(con):
    # DuckDB uses ?, Postgres uses %s
    if hasattr(con, "autocommit"): # Rough check for psycopg2 connection
        return "%s"
    return "?"


def _close_conn(con):
    if not con: return
    try:
        from agentwall.audit.write_queue import DBWriteQueue
        shared = DBWriteQueue.get()._con
        if con is shared:
            return # Skip closing shared connection
    except:
        pass
    
    if hasattr(con, "close"):
        con.close()


def init_db():
    con = _conn()
    
    # P0 Fix: Kubernetes + DuckDB concurrency warning
    # If we are in k8s and have more than 1 replica, DuckDB will corrupt data.
    # P0 Fix: Kubernetes + DuckDB concurrency warning
    db_path = os.getenv("AGENTWALL_DB", "agentwall_v2.duckdb")
    if "duckdb" in db_path.lower() and os.getenv("KUBERNETES_SERVICE_HOST"):
        # Fatal Error: Preventing DuckDB in K8s (Issue 3 Fix)
        print("\n" + "!"*80)
        print("CRITICAL: DuckDB detected in KUBERNETES environment.")
        print("DuckDB is an in-process database and cannot handle multi-replica file locking.")
        print("This WILL lead to database corruption and audit log loss.")
        print("ACTION: Set DATABASE_URL to a PostgreSQL instance.")
        print("!"*80 + "\n")
        raise SystemExit(1)

    con.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id    VARCHAR PRIMARY KEY,
            session_id  VARCHAR NOT NULL,
            agent_id    VARCHAR NOT NULL,
            call_id     VARCHAR NOT NULL,
            tool_name   VARCHAR NOT NULL,
            arguments   JSON,
            verdict     VARCHAR NOT NULL,
            reason      TEXT,
            details     JSON,
            mitre_id    VARCHAR DEFAULT '',
            source_fmt  VARCHAR DEFAULT 'unknown',
            latency_ms  DOUBLE DEFAULT 0,
            shadow_block BOOLEAN DEFAULT FALSE,
            chain_hash  VARCHAR NOT NULL,
            key_id      VARCHAR NOT NULL,
            ts          DOUBLE NOT NULL
        )
    """)
    con.execute("CREATE TABLE IF NOT EXISTS audit_roots (ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP, root TEXT)")
    con.execute("CREATE TABLE IF NOT EXISTS causal_graph (session_id VARCHAR PRIMARY KEY, graph_json TEXT)")
    for idx_sql in [
        "CREATE INDEX IF NOT EXISTS idx_session  ON audit_events(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_verdict  ON audit_events(verdict)",
        "CREATE INDEX IF NOT EXISTS idx_agent    ON audit_events(agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_mitre    ON audit_events(mitre_id)",
        "CREATE INDEX IF NOT EXISTS idx_ts       ON audit_events(ts)",
    ]:
        con.execute(idx_sql)
    _close_conn(con)


def _last_hash_internal(con) -> str:
    row = con.execute(
        "SELECT chain_hash FROM audit_events ORDER BY ts DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else "GENESIS"


def write_event(
    session_id: str, agent_id: str, call_id: str,
    tool_name: str, arguments: dict,
    verdict: str, reason: str, details: dict,
    mitre_id: str = "", source_fmt: str = "unknown",
    latency_ms: float = 0, shadow_block: bool = False,
) -> str:
    event_id   = str(uuid.uuid4())
    ts         = time.time()
    
    con = _conn()
    try:
        prev_hash  = _last_hash_internal(con)
        event_data = json.dumps({
            "event_id": event_id, "session_id": session_id,
            "agent_id": agent_id, "call_id": call_id,
            "tool_name": tool_name, "verdict": verdict,
            "mitre_id": mitre_id, "ts": ts,
        }, sort_keys=True)
        chain_hash = hmac.new(
            HMAC_KEY.encode(),
            (prev_hash + event_data).encode(),
            hashlib.sha256,
        ).hexdigest()

        placeholder = _get_placeholder(con)
        sql = f"""
            INSERT INTO audit_events
              (event_id, session_id, agent_id, call_id, tool_name,
               arguments, verdict, reason, details, mitre_id,
               source_fmt, latency_ms, shadow_block, chain_hash, key_id, ts)
            VALUES ({",".join([placeholder]*16)})
        """
        
        args = [
            event_id, session_id, agent_id, call_id, tool_name,
            json.dumps(arguments), verdict, reason, json.dumps(details), mitre_id,
            source_fmt, latency_ms, shadow_block, chain_hash, KEY_ID, ts,
        ]

        if hasattr(con, "autocommit"): # Postgres
            with con.cursor() as cur:
                cur.execute(sql, args)
                con.commit()
        else: # DuckDB
            con.execute(sql, args)
            
        return event_id
    finally:
        _close_conn(con)


# ─── Query helpers ────────────────────────────────────────────────────────────

def get_sessions(limit: int = 1000) -> list[dict]:
    con  = _conn()
    sql = f"""
        SELECT
            session_id, agent_id,
            COUNT(*) AS total_calls,
            SUM(CASE WHEN verdict='BLOCK'    THEN 1 ELSE 0 END) AS blocks,
            SUM(CASE WHEN verdict='AUDIT'    THEN 1 ELSE 0 END) AS audits,
            SUM(CASE WHEN verdict='SANITISE' THEN 1 ELSE 0 END) AS sanitised,
            MIN(ts) AS started_at,
            MAX(ts) AS last_seen,
            AVG(latency_ms) AS avg_latency_ms
        FROM audit_events
        GROUP BY session_id, agent_id
        ORDER BY last_seen DESC
        LIMIT {limit}
    """
    if hasattr(con, "autocommit"): # Postgres
        with con.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
    else: # DuckDB
        rows = con.execute(sql).fetchall()
    _close_conn(con)
    cols = ["session_id","agent_id","total_calls","blocks","audits",
            "sanitised","started_at","last_seen","avg_latency_ms"]
    return [dict(zip(cols, r)) for r in rows]


def get_session_events(session_id: str) -> list[dict]:
    con = _conn()
    placeholder = _get_placeholder(con)
    sql = f"""
        SELECT event_id, call_id, tool_name, arguments, verdict,
               reason, details, mitre_id, latency_ms, shadow_block, ts
        FROM audit_events
        WHERE session_id = {placeholder}
        ORDER BY ts ASC
    """
    if hasattr(con, "autocommit"): # Postgres
        with con.cursor() as cur:
            cur.execute(sql, [session_id])
            rows = cur.fetchall()
    else: # DuckDB
        rows = con.execute(sql, [session_id]).fetchall()
    _close_conn(con)
    cols = ["event_id","call_id","tool_name","arguments","verdict",
            "reason","details","mitre_id","latency_ms","shadow_block","ts"]
    result = []
    for r in rows:
        d = dict(zip(cols, r))
        d["arguments"] = json.loads(d["arguments"]) if d["arguments"] else {}
        d["details"]   = json.loads(d["details"])   if d["details"]   else {}
        result.append(d)
    return result


def get_violations(limit: int = 1000) -> list[dict]:
    con  = _conn()
    sql = f"""
        SELECT event_id, session_id, agent_id, tool_name,
               verdict, reason, mitre_id, ts
        FROM audit_events
        WHERE verdict IN ('BLOCK','AUDIT')
        ORDER BY ts DESC
        LIMIT {limit}
    """
    if hasattr(con, "autocommit"): # Postgres
        with con.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
    else: # DuckDB
        rows = con.execute(sql).fetchall()
    _close_conn(con)
    cols = ["event_id","session_id","agent_id","tool_name","verdict","reason","mitre_id","ts"]
    return [dict(zip(cols, r)) for r in rows]


def get_risk_scores() -> list[dict]:
    con  = _conn()
    rows = con.execute("""
        SELECT
            agent_id,
            COUNT(*) AS total,
            SUM(CASE WHEN verdict='BLOCK' THEN 3
                     WHEN verdict='AUDIT' THEN 1
                     ELSE 0 END) AS raw_score
        FROM audit_events
        GROUP BY agent_id
        ORDER BY raw_score DESC
    """).fetchall()
    _close_conn(con)
    result = []
    for agent_id, total, raw in rows:
        score = min(100, int((raw / max(total, 1)) * 100))
        result.append({"agent_id": agent_id, "risk_score": score, "total_calls": total})
    return result


def get_mitre_counts() -> list[dict]:
    """Returns per-MITRE-technique hit counts for the heatmap, enriched with details."""
    con  = _conn()
    rows = con.execute("""
        SELECT mitre_id, COUNT(*) AS count
        FROM audit_events
        WHERE mitre_id IS NOT NULL AND mitre_id != ''
          AND verdict IN ('BLOCK','AUDIT')
        GROUP BY mitre_id
        ORDER BY count DESC
        LIMIT 20
    """).fetchall()
    _close_conn(con)
    
    from agentwall.mitre import MITREMapper
    mapper = MITREMapper()
    
    result = []
    for mitre_id, count in rows:
        details = mapper.get_details(mitre_id)
        result.append({
            "mitre_id": mitre_id,
            "count":    count,
            "name":     details["name"],
            "tactic":   details["tactic"]
        })
    return result

def get_mitre_stats() -> list[dict]:
    return get_mitre_counts()

def get_campaigns() -> list[dict]:
    """Identify 'Campaigns' (clusters of related alerts) automatically."""
    con  = _conn()
    # Basic clustering: grouping alerts by session and agent within narrow windows
    rows = con.execute("""
        SELECT 
            session_id, agent_id, 
            MIN(ts) as start_ts, MAX(ts) as end_ts,
            COUNT(*) as hit_count,
            LIST(DISTINCT mitre_id) as techniques
        FROM audit_events
        WHERE verdict IN ('BLOCK', 'AUDIT')
        GROUP BY session_id, agent_id
        HAVING hit_count > 0
        ORDER BY start_ts DESC
        LIMIT 20
    """).fetchall()
    _close_conn(con)
    
    result = []
    for r in rows:
        result.append({
            "id": f"CAMP-{r[0][:8]}",
            "name": f"Security Event: {r[1]}",
            "session_id": r[0],
            "agent_id": r[1],
            "start_ts": r[2],
            "end_ts": r[3],
            "hit_count": r[4],
            "is_active": (time.time() - r[3]) < 300, # Active if hit in last 5 mins
            "techniques": [t for t in r[5] if t]
        })
    return result


def get_latency_percentiles() -> dict:
    """For performance analytics — p50/p95/p99 latency."""
    con  = _conn()
    row  = con.execute("""
        SELECT
            PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_ms) AS p50,
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95,
            PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ms) AS p99,
            AVG(latency_ms) AS avg
        FROM audit_events
        WHERE latency_ms > 0
    """).fetchone()
    _close_conn(con)
    if row:
        return {"p50": row[0], "p95": row[1], "p99": row[2], "avg": row[3]}
    return {}


def save_causal_graph(session_id: str, graph_json: str):
    con = _conn()
    con.execute("INSERT OR REPLACE INTO causal_graph VALUES (?, ?)", (session_id, graph_json))
    con.commit()

def load_all_causal_graphs():
    con = _conn()
    rows = con.execute("SELECT session_id, graph_json FROM causal_graph").fetchall()
    return {r[0]: r[1] for r in rows}


def get_global_stats() -> dict:
    """Aggregates all-time stats for dashboard seeding."""
    print("[Schema] Fetching global stats...")
    try:
        con = _conn()
        # Verdict counts
        v_sql = "SELECT verdict, COUNT(*) FROM audit_events GROUP BY verdict"
        verdicts = dict(con.execute(v_sql).fetchall())
        
        # MITRE technique counts
        m_sql = "SELECT mitre_id, COUNT(*) FROM audit_events WHERE mitre_id != '' GROUP BY mitre_id"
        mitre = dict(con.execute(m_sql).fetchall())
        
        # Tool usage counts
        t_sql = "SELECT tool_name, COUNT(*) FROM audit_events GROUP BY tool_name"
        tools = dict(con.execute(t_sql).fetchall())
        
        # Policy violation counts (extracting from JSON details)
        p_sql = """
            SELECT json_extract_string(details, '$.policy.rule'), COUNT(*) 
            FROM audit_events 
            WHERE verdict IN ('BLOCK', 'AUDIT') 
            AND json_extract_string(details, '$.policy.rule') IS NOT NULL
            GROUP BY 1
        """
        policies = dict(con.execute(p_sql).fetchall())
        
        print(f"[Schema] Stats fetched: {len(verdicts)} verdicts, {len(mitre)} mitre, {len(tools)} tools, {len(policies)} policies")
        return {
            "verdicts": verdicts, 
            "mitre": mitre,
            "tools": tools,
            "policies": policies
        }
    except Exception as e:
        print(f"[Schema] [ERROR] Global stats fetch failed: {e}")
        return {"verdicts": {}, "mitre": {}, "tools": {}, "policies": {}}
