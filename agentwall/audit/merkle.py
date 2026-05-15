"""
Merkle Tree Audit Log.

Why Merkle instead of HMAC chain?
  • HMAC chain: to verify event N, you must re-verify events 1..N-1
  • Merkle tree: to verify any single event, you need O(log n) sibling hashes
  • Publishable root hash: post the root hash publicly (like CT log operators)
    and anyone can prove an event is (or isn't) in the log.

Structure:
  Each leaf = SHA-256(event_json)
  Each internal node = SHA-256(left_child || right_child)
  Root = SHA-256 of entire log, publishable
"""
import hashlib
import json
import os
from pathlib import Path

DB_PATH = os.getenv("AGENTWALL_DB", "/tmp/agentwall.duckdb")


def sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _leaf_hash(event: dict) -> str:
    canonical = json.dumps(event, sort_keys=True, separators=(',',':'))
    return sha256(canonical)


def _build_tree(leaves: list[str]) -> list[list[str]]:
    """Build Merkle tree from leaf hashes. Returns list of levels."""
    if not leaves:
        return [[sha256("empty")]]
    level = list(leaves)
    tree  = [list(level)]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicate last leaf
        level = [sha256(level[i] + level[i+1]) for i in range(0, len(level), 2)]
        tree.append(list(level))
    return tree


def _proof_path(tree: list[list[str]], leaf_index: int) -> list[dict]:
    """Return the Merkle proof path for a given leaf index."""
    proof = []
    idx   = leaf_index
    for level in tree[:-1]:  # skip root level
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
        side        = "right" if idx % 2 == 0 else "left"
        if sibling_idx < len(level):
            proof.append({"hash": level[sibling_idx], "side": side})
        idx //= 2
    return proof


class MerkleAuditLog:
    def __init__(self):
        import duckdb
        self._db_path = os.getenv("AGENTWALL_DB", "agentwall.duckdb")

    def _get_all_events(self, con=None) -> list[dict]:
        import duckdb
        close_later = False
        if con is None:
            con = duckdb.connect(self._db_path)
            close_later = True
            
        rows = con.execute(
            "SELECT event_id, session_id, agent_id, tool_name, verdict, ts "
            "FROM audit_events ORDER BY ts ASC"
        ).fetchall()
        
        if close_later:
            con.close()
            
        cols = ["event_id","session_id","agent_id","tool_name","verdict","ts"]
        return [dict(zip(cols, r)) for r in rows]

    def compute_root(self, con=None) -> str:
        events = self._get_all_events(con=con)
        if not events:
            return sha256("empty_log")
        leaves = [_leaf_hash(e) for e in events]
        tree   = _build_tree(leaves)
        return tree[-1][0]

    def publish_root(self, con=None):
        """Persist the current root hash as the 'last known good' root."""
        root = self.compute_root(con=con)
        import duckdb
        close_later = False
        if con is None:
            con = duckdb.connect(self._db_path)
            close_later = True
            
        con.execute("CREATE TABLE IF NOT EXISTS audit_roots (ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP, root TEXT)")
        con.execute("INSERT INTO audit_roots (root) VALUES (?)", [root])
        
        if close_later:
            con.close()
            
        return root

    def verify(self) -> tuple[bool, str]:
        """
        P0 Fix: Actually verify the log.
        Compares current compute_root() with the last published root.
        """
        current_root = self.compute_root()
        
        import duckdb
        con = duckdb.connect(self._db_path)
        try:
            row = con.execute("SELECT root FROM audit_roots ORDER BY ts DESC LIMIT 1").fetchone()
            if not row:
                # Issue 3 Fix: If no root published yet, log is unverified (cannot prove integrity)
                return False, "NO_PUBLISHED_ROOT"
            
            stored_root = row[0]
            is_valid = (current_root == stored_root)
            return is_valid, current_root
        except Exception:
            # Table might not exist — also unverified
            return False, "LOG_SCHEMA_UNINITIALIZED"
        finally:
            con.close()

    def proof_of_inclusion(self, event_id: str) -> dict | None:
        """Return Merkle proof that event_id is in the log."""
        events = self._get_all_events()
        ids    = [e["event_id"] for e in events]
        if event_id not in ids:
            return None
        idx    = ids.index(event_id)
        leaves = [_leaf_hash(e) for e in events]
        tree   = _build_tree(leaves)
        return {
            "event_id":   event_id,
            "leaf_hash":  leaves[idx],
            "root":       tree[-1][0],
            "proof_path": _proof_path(tree, idx),
            "leaf_index": idx,
            "total_events": len(events),
        }
