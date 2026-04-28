"""
Universal tool-call normaliser v2.

Supports:
  - Anthropic tool_use (claude-3+)
  - OpenAI function_call (legacy) and tool_calls (new)
  - LangChain AgentAction
  - CrewAI tool output format
  - AutoGen tool call format
  - Raw canonical format (AgentWall native)

All formats are normalised to:
{
  "session_id":  str,
  "agent_id":    str,
  "call_id":     str,
  "tool_name":   str,
  "arguments":   dict,
  "context":     str | None,
  "timestamp":   float,
  "source_fmt":  str,       # which format it came from (for telemetry)
}
"""
import json
import time
import uuid
from typing import Any


def normalise_raw(payload: dict) -> dict:
    """Detect format and normalise to canonical AgentWall schema."""

    # ── Anthropic tool_use ─────────────────────────────────────────────────
    if payload.get("type") == "tool_use":
        return _mk(
            session_id = payload.get("session_id", str(uuid.uuid4())),
            agent_id   = payload.get("agent_id", "unknown"),
            call_id    = payload.get("id", str(uuid.uuid4())),
            tool_name  = payload["name"],
            arguments  = payload.get("input", {}),
            context    = payload.get("context"),
            timestamp  = payload.get("timestamp", time.time()),
            source_fmt = "anthropic",
        )

    # ── OpenAI new tool_calls format ───────────────────────────────────────
    if payload.get("type") == "function" and "function" in payload:
        fn   = payload["function"]
        args = fn.get("arguments", "{}")
        if isinstance(args, str):
            try:    args = json.loads(args)
            except: args = {"raw": args}
        return _mk(
            session_id = payload.get("session_id", str(uuid.uuid4())),
            agent_id   = payload.get("agent_id", "unknown"),
            call_id    = payload.get("id", str(uuid.uuid4())),
            tool_name  = fn["name"],
            arguments  = args,
            context    = payload.get("context"),
            timestamp  = payload.get("timestamp", time.time()),
            source_fmt = "openai",
        )

    # ── OpenAI legacy function_call ────────────────────────────────────────
    if "function_call" in payload:
        fc   = payload["function_call"]
        args = fc.get("arguments", "{}")
        if isinstance(args, str):
            try:    args = json.loads(args)
            except: args = {"raw": args}
        return _mk(
            session_id = payload.get("session_id", str(uuid.uuid4())),
            agent_id   = payload.get("agent_id", "unknown"),
            call_id    = str(uuid.uuid4()),
            tool_name  = fc["name"],
            arguments  = args,
            context    = payload.get("context"),
            timestamp  = payload.get("timestamp", time.time()),
            source_fmt = "openai_legacy",
        )

    # ── LangChain AgentAction ──────────────────────────────────────────────
    if "tool" in payload and ("tool_input" in payload or "log" in payload):
        tool_input = payload.get("tool_input", {})
        if isinstance(tool_input, str):
            try:    tool_input = json.loads(tool_input)
            except: tool_input = {"input": tool_input}
        return _mk(
            session_id = payload.get("session_id", str(uuid.uuid4())),
            agent_id   = payload.get("agent_id", "unknown"),
            call_id    = str(uuid.uuid4()),
            tool_name  = payload["tool"],
            arguments  = tool_input,
            context    = payload.get("log"),
            timestamp  = payload.get("timestamp", time.time()),
            source_fmt = "langchain",
        )

    # ── CrewAI format ──────────────────────────────────────────────────────
    if "action" in payload and "action_input" in payload:
        action_input = payload["action_input"]
        if isinstance(action_input, str):
            try:    action_input = json.loads(action_input)
            except: action_input = {"input": action_input}
        return _mk(
            session_id = payload.get("session_id", str(uuid.uuid4())),
            agent_id   = payload.get("agent_id", "unknown"),
            call_id    = str(uuid.uuid4()),
            tool_name  = payload["action"],
            arguments  = action_input,
            context    = payload.get("thought") or payload.get("context"),
            timestamp  = payload.get("timestamp", time.time()),
            source_fmt = "crewai",
        )

    # ── AutoGen format ─────────────────────────────────────────────────────
    if "role" in payload and payload.get("role") == "tool" and "content" in payload:
        content = payload["content"]
        if isinstance(content, str):
            try:    content = json.loads(content)
            except: content = {"raw": content}
        return _mk(
            session_id = payload.get("session_id", str(uuid.uuid4())),
            agent_id   = payload.get("agent_id", "unknown"),
            call_id    = str(uuid.uuid4()),
            tool_name  = payload.get("name", "unknown"),
            arguments  = content,
            context    = None,
            timestamp  = payload.get("timestamp", time.time()),
            source_fmt = "autogen",
        )

    # ── Already canonical ──────────────────────────────────────────────────
    if "tool_name" in payload:
        payload.setdefault("session_id", str(uuid.uuid4()))
        payload.setdefault("agent_id", "unknown")
        payload.setdefault("call_id", str(uuid.uuid4()))
        payload.setdefault("timestamp", time.time())
        payload.setdefault("source_fmt", "canonical")
        return payload

    raise ValueError(
        f"Cannot normalise payload — unrecognised format. Keys: {list(payload.keys())}"
    )


def _mk(session_id, agent_id, call_id, tool_name,
        arguments, context, timestamp, source_fmt) -> dict:
    return {
        "session_id": session_id,
        "agent_id":   agent_id,
        "call_id":    call_id,
        "tool_name":  tool_name,
        "arguments":  arguments if isinstance(arguments, dict) else {"value": arguments},
        "context":    context,
        "timestamp":  float(timestamp),
        "source_fmt": source_fmt,
    }
