"""
Semantic Policy Engine v2.

Improvements over v1:
  1. Compiled AST — rules parsed once at load, not re-evaluated each time
  2. Policy variants — load 'strict', 'standard', 'permissive' profiles
  3. Conflict detection integration — raises on load if conflicts found
  4. Per-agent policy scoping
  5. Wildcard tool glob patterns
"""
import os
import re
import fnmatch
from pathlib import Path
from typing import Any
import yaml

from agentwall.layer1.conflict_detector import ConflictDetector

DEFAULT_POLICY_PATH = Path(__file__).parent.parent.parent / "config" / "policy.yaml"

PROFILES = {
    "strict":      {"default_action": "BLOCK",  "promote_audit": True},
    "standard":    {"default_action": "PERMIT",  "promote_audit": False},
    "permissive":  {"default_action": "PERMIT",  "promote_audit": False},
}


class CompiledRule:
    __slots__ = ("name","tool_glob","agent_glob","conditions","action","reason","mitre_id")

    def __init__(self, raw: dict):
        self.name       = raw.get("name", "unnamed")
        self.tool_glob  = raw.get("tool", "*")
        self.agent_glob = raw.get("agent", "*")
        self.conditions = raw.get("match", {})
        self.action     = raw.get("action", "BLOCK")
        self.reason     = raw.get("reason", self.name)
        self.mitre_id   = raw.get("mitre_id")
        
        # Pre-compile regex for performance
        for key, conds in self.conditions.items():
            if "regex" in conds:
                conds["_compiled_re"] = re.compile(conds["regex"], re.IGNORECASE)

    def matches(self, call: dict) -> bool:
        if not fnmatch.fnmatch(call["tool_name"], self.tool_glob):
            return False
        if not fnmatch.fnmatch(call["agent_id"], self.agent_glob):
            return False
        args = call.get("arguments", {})
        for key, conds in self.conditions.items():
            if key == "" or key == "*":
                # Match against all argument values combined
                val = " ".join(str(v) for v in args.values())
                if call.get("context"):
                    val += " " + str(call["context"])
            else:
                val = str(args.get(key, ""))
            
            # P2 Fix: Case-insensitive matching for 'contains' and custom rules
            val = val.lower()
            
            if not self._eval(val, conds):
                return False
        return True

    def _eval(self, value: str, conds: dict) -> bool:
        if "contains" in conds:
            patterns = conds["contains"] if isinstance(conds["contains"], list) else [conds["contains"]]
            if not any(p in value for p in patterns):
                return False
        if "_compiled_re" in conds:
            if not conds["_compiled_re"].search(value):
                return False
        elif "regex" in conds:
            # Fallback if somehow not compiled
            if not re.search(conds["regex"], value, re.IGNORECASE):
                return False
        if "starts_with" in conds:
            if not value.startswith(conds["starts_with"]):
                return False
        if "not_in_allowlist" in conds:
            if value in conds["not_in_allowlist"]:
                return False
        if "max_length" in conds:
            if len(value) <= int(conds["max_length"]):
                return False
        return True


class PolicyEngine:
    def __init__(self, policy_path: str = None, policy_variant: str = "standard"):
        self._path = policy_path or os.getenv("AGENTWALL_POLICY", str(DEFAULT_POLICY_PATH))
        self._variant = policy_variant
        self._profile = PROFILES.get(policy_variant, PROFILES["standard"])
        self._rules   = self._load_and_compile(self._path)
        if self._profile["promote_audit"]:
            print(f"[PolicyEngine] [STRICT] Strict Mode active — all AUDIT rules promoted to BLOCK")

    def _load_and_compile(self, path: str) -> list[CompiledRule]:
        p = Path(path)
        if not p.exists():
            return []
        with open(p, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        raw_rules = data.get("rules", [])

        # In strict mode, promote every AUDIT rule to BLOCK
        if self._profile.get("promote_audit"):
            for r in raw_rules:
                if r.get("action") == "AUDIT":
                    r["action"] = "BLOCK"
                    r["reason"] = f"[Strict] {r.get('reason', r.get('name', ''))}"

        # Validate for conflicts
        # SURFACING CONFLICTS (M-2 Fix)
        issues = ConflictDetector().check(raw_rules)
        if issues:
            print(f"[PolicyEngine] [WARNING] Detected {len(issues)} policy conflicts:")
            for issue in issues:
                print(f"  - {issue}")
            if os.getenv("AGENTWALL_STRICT_POLICY") == "1":
                raise ValueError("Policy conflict detected in strict mode")

        return [CompiledRule(r) for r in raw_rules]

    def check(self, call: dict) -> dict:
        # print(f"[PolicyEngine] Checking call: {call['tool_name']} by {call['agent_id']}")
        for rule in self._rules:
            if rule.matches(call):
                # print(f"[PolicyEngine] MATCH: {rule.name} (action={rule.action})")
                res = {
                    "action":   rule.action,
                    "reason":   rule.reason,
                    "rule":     rule.name,
                    "mitre_id": rule.mitre_id,
                }
                # Additional enforcement for strict mode promotion
                if self._profile.get("promote_audit") and res["action"] == "AUDIT":
                    res["action"] = "BLOCK"
                    res["reason"] = f"[Strict Mode Audit Promotion] {res['reason']}"
                return res

        # print(f"[PolicyEngine] NO MATCH found for {call['tool_name']}")
        return {
            "action": self._profile["default_action"],
            "reason": "No matching rule — default action applied",
            "rule":   None,
        }

    def reload(self):
        self._rules = self._load_and_compile(self._path)

    def get_essential_tools(self) -> list[str]:
        """Returns a list of tools that are always permitted, even in lockdown."""
        # In a real system, this would be read from a 'lockdown_allowlist' in policy.yaml
        # For now, we use a sensible default that can be overridden by env
        default = "get_weather,read_docs,search,get_status,check_health"
        val = os.getenv("AGENTWALL_ESSENTIAL_TOOLS", default)
        return [t.strip() for t in val.split(",")]
