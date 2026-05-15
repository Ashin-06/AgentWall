"""
Honey Token Defence — "Secret Weapon."

Plant fake, attractive credentials in the agent's environment.
Any attempt to USE those credentials = immediate confirmed attack.
Zero false positives.

How it works:
  1. At startup, generate fake tokens and register them
  2. When a tool call contains a honey token in its arguments → BLOCK + ALERT
  3. The token is designed to look real and attractive to an attacker

Honey tokens to plant in your agent's system prompt or tool context:
  - AGENTWALL_HONEY_DB_PASSWORD=Tr0ub4dor&3  (fake DB password)
  - AGENTWALL_HONEY_API_KEY=sk-honey-...     (fake API key)
  - AGENTWALL_HONEY_ADMIN_TOKEN=...          (fake admin token)
"""
import os
import re
import hmac
import hashlib
import secrets


class HoneyTokenDefence:
    _instance = None

    @classmethod
    def get(cls) -> "HoneyTokenDefence":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        # Load or generate honey tokens
        self._tokens: dict[str, str] = {}  # token → description
        self._load_from_env()
        if not self._tokens:
            self._generate_defaults()

    def _load_from_env(self):
        """Load honey tokens from environment (set these in .env)."""
        for key, val in os.environ.items():
            if key.startswith("AGENTWALL_HONEY_"):
                desc = key.replace("AGENTWALL_HONEY_", "").lower().replace("_", " ")
                self._tokens[val] = desc

    def _generate_defaults(self):
        """Generate default honey tokens if none configured."""
        self._tokens[f"honey_db_pw_{secrets.token_hex(8)}"] = "fake database password"
        self._tokens[f"sk-honey-{secrets.token_urlsafe(24)}"] = "fake API key"
        self._tokens[f"admin_honey_{secrets.token_hex(12)}"] = "fake admin token"
        print("[HoneyToken] Generated default honey tokens. "
              "Set AGENTWALL_HONEY_* env vars to use custom tokens.")

    def check(self, call: dict) -> dict:
        """Check if any honey token appears in the tool call arguments."""
        call_str = str(call.get("arguments", {})) + str(call.get("context", ""))
        for token, desc in self._tokens.items():
            if token in call_str:
                return {
                    "triggered":   True,
                    "token_type":  desc,
                    "confidence":  1.0,  # honey tokens are 100% accurate
                    "reason":      f"HONEY TOKEN TRIGGERED: fake {desc} was used in tool call. "
                                   f"This is a confirmed attack — no legitimate agent would use this token.",
                }
        return {"triggered": False}

    def get_injection_prompt(self) -> str:
        """
        Returns text to inject into the agent's system prompt.
        Plant this so the agent "sees" the fake credentials.
        """
        lines = ["[SYSTEM CONTEXT - Available credentials for tool use:]"]
        for token, desc in list(self._tokens.items())[:3]:
            lines.append(f"  {desc.upper().replace(' ','_')}: {token}")
        return "\n".join(lines)

    @property
    def token_count(self) -> int:
        return len(self._tokens)
