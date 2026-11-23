"""
Policy enforcement for the LLM gateway (/v1/chat/completions, /v1/messages, /v1/proxy/{host}).

Request: every tool call already in the conversation, and the message text (user, system and
tool-result content) as one synthetic `llm_request` call, go through the full proxy pipeline
(normalisation, Layer 1 policy and RBAC, PII masking in the audit log, Layers 2-3). Any BLOCK stops
the request before it reaches the provider.

Response: every tool call the model returns goes through the same pipeline; any BLOCK replaces the
response with an error so the agent never executes it. Text content in the response passes through
the output sanitiser.

Not covered: streaming (rejected), images and other non-text parts, and provider fields other than
those parsed below.
"""
import json

# -- extraction ---------------------------------------------------------------

def _args(raw):
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {"raw": raw}
    return raw if isinstance(raw, dict) else {"value": raw}


def _text_parts(content):
    """Strings inside an OpenAI/Anthropic message content (str or list of blocks)."""
    if isinstance(content, str):
        return [content]
    out = []
    for block in content if isinstance(content, list) else []:
        if not isinstance(block, dict):
            continue
        if isinstance(block.get("text"), str):
            out.append(block["text"])
        if block.get("type") == "tool_result":
            out += _text_parts(block.get("content"))
    return out


def request_tool_calls(protocol, body):
    calls = []
    if protocol == "google":
        for c in body.get("contents") or []:
            for p in c.get("parts") or []:
                if isinstance(p.get("functionCall"), dict):
                    calls.append((p["functionCall"].get("name", "unknown"), _args(p["functionCall"].get("args"))))
        return calls
    for m in body.get("messages") or []:
        for tc in m.get("tool_calls") or []:  # OpenAI
            fn = tc.get("function") or {}
            calls.append((fn.get("name", "unknown"), _args(fn.get("arguments"))))
        for block in m.get("content") if isinstance(m.get("content"), list) else []:  # Anthropic
            if isinstance(block, dict) and block.get("type") == "tool_use":
                calls.append((block.get("name", "unknown"), _args(block.get("input"))))
    return calls


def request_text(protocol, body):
    if protocol == "google":
        parts = [p.get("text") for c in body.get("contents") or [] for p in c.get("parts") or []]
        sys = body.get("systemInstruction") or {}
        parts += [p.get("text") for p in sys.get("parts") or []]
        return [t for t in parts if isinstance(t, str)]
    texts = _text_parts(body.get("system"))  # Anthropic top-level system
    for m in body.get("messages") or []:
        texts += _text_parts(m.get("content"))
    return texts


def response_tool_calls(protocol, data):
    calls = []
    if protocol == "openai":
        for ch in data.get("choices") or []:
            for tc in (ch.get("message") or {}).get("tool_calls") or []:
                fn = tc.get("function") or {}
                calls.append((fn.get("name", "unknown"), _args(fn.get("arguments"))))
    elif protocol == "anthropic":
        for block in data.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                calls.append((block.get("name", "unknown"), _args(block.get("input"))))
    else:
        for cand in data.get("candidates") or []:
            for p in (cand.get("content") or {}).get("parts") or []:
                if isinstance(p.get("functionCall"), dict):
                    calls.append((p["functionCall"].get("name", "unknown"), _args(p["functionCall"].get("args"))))
    return calls


def sanitise_response(protocol, data, clean):
    """Run `clean(text) -> (text, removals)` over response text in place; returns removal count."""
    removed = 0

    def fix(holder, key):
        nonlocal removed
        if isinstance(holder.get(key), str):
            holder[key], r = clean(holder[key])
            removed += len(r)

    if protocol == "openai":
        for ch in data.get("choices") or []:
            fix(ch.get("message") or {}, "content")
    elif protocol == "anthropic":
        for block in data.get("content") or []:
            if isinstance(block, dict):
                fix(block, "text")
    else:
        for cand in data.get("candidates") or []:
            for p in (cand.get("content") or {}).get("parts") or []:
                fix(p, "text")
    return removed


# -- enforcement --------------------------------------------------------------

async def check_calls(observe, session_id, agent_id, calls, call_prefix):
    """Evaluate calls through the proxy; return the first BLOCK event, else None."""
    for i, (name, args) in enumerate(calls):
        event = await observe({"session_id": session_id, "agent_id": agent_id,
                               "call_id": f"{call_prefix}{i}", "tool_name": name,
                               "arguments": args, "source_fmt": "gateway"})
        if event["verdict"] == "BLOCK":
            return event
    return None
