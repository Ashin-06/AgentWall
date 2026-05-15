"""
Semantic Policy Compiler — write rules in plain English, get YAML back.

Examples:
  "this agent may not write files outside /workspace"
  →  tool: write_file, match: {path: {regex: "^(?!/workspace)"}}, action: BLOCK

  "block any shell command that downloads and executes code"
  →  tool: bash, match: {command: {regex: "(curl|wget).*(|bash|sh)"}}, action: BLOCK

Uses Claude to do the NL → structured rule translation.
The compiled output is validated before use.
"""
import json
import os
import re
import httpx


COMPILER_SYSTEM = """You are a security policy compiler for AgentWall, a runtime firewall for AI agents.
Convert the natural language security rule into a YAML policy rule dict.

Output ONLY valid JSON (no markdown, no explanation):
{
  "name": "<short name>",
  "tool": "<tool name or *>",
  "match": {
    "<argument_key>": {
      "<condition_type>": "<value>"
    }
  },
  "action": "BLOCK|AUDIT|PERMIT",
  "reason": "<human-readable reason shown when rule fires>"
}

Condition types: contains (list), regex (string), starts_with (string), not_in_allowlist (list)
If the rule is about all tools, use tool: "*"
If no argument matching is needed, omit "match"."""


class SemanticPolicyCompiler:
    def __init__(self):
        self.api_key      = os.getenv("ANTHROPIC_API_KEY")
        self.ollama_model = os.getenv("OLLAMA_MODEL")
        self.ollama_base  = os.getenv("OLLAMA_API_BASE", "http://localhost:11434")
        self.model        = "claude-haiku-4-5-20251001"

    async def compile(self, nl_rules: list[str]) -> list[dict]:
        """Compile a list of natural language rules into policy dicts."""
        compiled = []
        for rule_text in nl_rules:
            result = await self._compile_one(rule_text)
            if result:
                compiled.append(result)
        return compiled

    async def _compile_one(self, rule_text: str) -> dict | None:
        if not self.api_key and not self.ollama_model:
            return {"error": "No API key or Ollama model — cannot compile NL policy", "input": rule_text}
            
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                if self.ollama_model:
                    payload = {
                        "model": self.ollama_model,
                        "messages": [
                            {"role": "system", "content": COMPILER_SYSTEM},
                            {"role": "user", "content": rule_text}
                        ],
                        "stream": False,
                        "format": "json"
                    }
                    r = await client.post(
                        f"{self.ollama_base.rstrip('/')}/api/chat",
                        json=payload,
                    )
                    r.raise_for_status()
                    text = r.json()["message"]["content"].strip()
                else:
                    payload = {
                        "model": self.model,
                        "max_tokens": 512,
                        "system": COMPILER_SYSTEM,
                        "messages": [{"role": "user", "content": rule_text}],
                    }
                    r = await client.post(
                        "https://api.anthropic.com/v1/messages",
                        headers={"x-api-key": self.api_key,
                                 "anthropic-version": "2023-06-01",
                                 "content-type": "application/json"},
                        json=payload,
                    )
                    r.raise_for_status()
                    text = r.json()["content"][0]["text"].strip()
                text = re.sub(r"```[a-z]*\n?", "", text).strip("`").strip()
                rule = json.loads(text)
                rule["_source"] = "nl_compiled"
                rule["_nl_input"] = rule_text
                return rule
        except Exception as e:
            return {"error": str(e), "input": rule_text}
