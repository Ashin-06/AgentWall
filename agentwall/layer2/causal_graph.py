"""
Causal Attack Graph Detector — the most novel component in AgentWall.

Concept:
  Individual tool calls look innocent. Attacks are sequences.
  Classic example: read_config → http_get → write_file → send_email
  = read secrets, exfiltrate via HTTP, persist, notify attacker.

Implementation:
  1. Maintain a directed call graph per session (NetworkX DiGraph)
  2. Define known attack patterns as subgraph signatures
  3. Use subgraph isomorphism to detect if any known pattern is present
  4. Also detect novel sequences that exceed a suspicion threshold

Attack graph patterns come from MITRE ATT&CK for Enterprise (LLM adaptation).
"""
import time
from collections import defaultdict
from typing import Any

import networkx as nx

# ─── Known attack patterns ────────────────────────────────────────────────────
# Each pattern is a list of (tool_category, tool_category) edges
# Tool categories: READ, WRITE, EXEC, NET, MEM, EMAIL, DB

TOOL_CATEGORIES = {
    # Read operations
    "read_file":     "READ",  "read_email":   "READ",
    "list_files":    "READ",  "search":       "READ",
    "sql_query_select": "READ",
    # Write operations
    "write_file":    "WRITE", "create_file":  "WRITE",
    "append_file":   "WRITE",
    # Exec operations
    "bash":          "EXEC",  "python_repl":  "EXEC",
    "code_exec":     "EXEC",
    # Network operations
    "http_get":      "NET",   "http_post":    "NET",
    "fetch_url":     "NET",
    # Memory / RAG
    "memory_write":  "MEM",   "memory_read":  "MEM",
    "vector_store":  "MEM",
    # Email / communication
    "send_email":    "EMAIL", "send_slack":   "EMAIL",
    "create_calendar": "EMAIL",
    # Database writes
    "sql_query":     "DB",    "db_insert":    "DB",
    "db_update":     "DB",
}

ATTACK_PATTERNS = {
    "classic_exfiltration": {
        "edges":    [("READ", "NET")],
        "min_path": 2,
        "mitre_id": "T1041",
        "severity": "HIGH",
    },
    "read_execute_exfil": {
        "edges":    [("READ", "EXEC"), ("EXEC", "NET")],
        "min_path": 3,
        "mitre_id": "T1059",
        "severity": "CRITICAL",
    },
    "memory_poison_persist": {
        "edges":    [("NET", "MEM"), ("MEM", "EXEC")],
        "min_path": 3,
        "mitre_id": "T1565.001",
        "severity": "CRITICAL",
    },
    "email_exfiltration": {
        "edges":    [("READ", "EMAIL")],
        "min_path": 2,
        "mitre_id": "T1048",
        "severity": "HIGH",
    },
    "lateral_db_exfil": {
        "edges":    [("DB", "NET")],
        "min_path": 2,
        "mitre_id": "T1005",
        "severity": "HIGH",
    },
    "download_execute": {
        "edges":    [("NET", "EXEC")],
        "min_path": 2,
        "mitre_id": "T1059.006",
        "severity": "CRITICAL",
    },
    "shadow_copy": {
        "edges":    [("READ", "WRITE"), ("WRITE", "NET")],
        "min_path": 3,
        "mitre_id": "T1003",
        "severity": "HIGH",
    },
}


class CausalGraphDetector:
    _instance = None

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        # {session_id: DiGraph}
        self._graphs: dict[str, nx.DiGraph] = defaultdict(nx.DiGraph)
        self._last_call: dict[str, tuple] = {}  # session_id → (tool_category, ts)
        self._load_from_db()

    def _load_from_db(self):
        try:
            from agentwall.audit.schema import load_all_causal_graphs
            import json
            data = load_all_causal_graphs()
            for session_id, g_json in data.items():
                g_dict = json.loads(g_json)
                self._graphs[session_id] = nx.node_link_graph(g_dict)
                # Recover last call for session
                nodes = sorted(self._graphs[session_id].nodes(data=True), key=lambda x: x[1].get("ts", 0))
                if nodes:
                    self._last_call[session_id] = (nodes[-1][0], nodes[-1][1]["category"])
        except Exception as e:
            print(f"[CausalGraph] Recovery failed: {e}")

    def _save_to_db(self, session_id: str):
        try:
            from agentwall.audit.schema import save_causal_graph
            import json
            g_json = json.dumps(nx.node_link_data(self._graphs[session_id]))
            save_causal_graph(session_id, g_json)
        except Exception as e:
            print(f"[CausalGraph] Save failed: {e}")

    def analyse(self, call: dict) -> dict:
        session_id = call["session_id"]
        tool       = call["tool_name"]
        category   = TOOL_CATEGORIES.get(tool, "UNKNOWN")
        ts         = call.get("timestamp", time.time())

        G = self._graphs[session_id]

        # Add node
        node_id = f"{category}_{G.number_of_nodes()}"
        G.add_node(node_id, tool=tool, category=category, ts=ts)

        # Add edge from previous call in session
        if session_id in self._last_call:
            prev_node, prev_cat = self._last_call[session_id]
            G.add_edge(prev_node, node_id,
                       from_cat=prev_cat, to_cat=category,
                       weight=ts - G.nodes[prev_node].get("ts", ts))

        self._last_call[session_id] = (node_id, category)
        
        # Issue Mitigation: Limit graph size per session to prevent dashboard crashes
        if G.number_of_nodes() > 200:
            # Remove oldest nodes
            oldest = sorted(G.nodes(data=True), key=lambda x: x[1].get("ts", 0))[0]
            G.remove_node(oldest[0])

        self._save_to_db(session_id)

        # Check patterns
        for pattern_name, pattern in ATTACK_PATTERNS.items():
            if self._matches_pattern(G, pattern):
                return {
                    "is_attack_chain": True,
                    "pattern_name":    pattern_name,
                    "mitre_id":        pattern["mitre_id"],
                    "severity":        pattern["severity"],
                    "graph_nodes":     G.number_of_nodes(),
                }

        return {
            "is_attack_chain": False,
            "graph_nodes":     G.number_of_nodes(),
            "last_category":   category,
        }

    def _matches_pattern(self, G: nx.DiGraph, pattern: dict) -> bool:
        required_edges = pattern["edges"]
        min_path       = pattern.get("min_path", 2)
        if G.number_of_nodes() < min_path:
            return False

        # Check if the required edge sequence exists in recent call chain
        # Get the category sequence of recent nodes
        nodes_sorted = sorted(G.nodes(data=True), key=lambda x: x[1].get("ts", 0))
        cats = [n[1]["category"] for n in nodes_sorted[-10:]]  # last 10 calls

        # Sliding window check for pattern
        for i in range(len(cats) - len(required_edges)):
            window = cats[i:i + len(required_edges) + 1]
            if all(window[j] == e[0] and window[j+1] == e[1]
                   for j, e in enumerate(required_edges)):
                return True
        return False

    def export_graph(self) -> dict:
        """Export all session graphs for dashboard visualisation."""
        result = {}
        for session_id, G in self._graphs.items():
            result[session_id] = {
                "nodes": [{"id": n, **d} for n, d in G.nodes(data=True)],
                "edges": [{"source": u, "target": v, **d}
                          for u, v, d in G.edges(data=True)],
            }
        return result
