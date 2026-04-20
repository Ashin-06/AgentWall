"""
Explainability Engine — byte-range attribution + MITRE ATT&CK mapping.

When a verdict is BLOCK or AUDIT, this engine:
  1. Finds the exact substring(s) that triggered the detection
  2. Maps the attack to a MITRE ATT&CK technique ID
  3. Returns a human-readable explanation suitable for a SOC analyst

This is what makes AgentWall citable: the output is structured,
auditable, and maps to a published threat taxonomy.
"""
import re
from agentwall.mitre import MITREMapper


class ExplainabilityEngine:
    def __init__(self):
        self.mitre = MITREMapper()

    async def attribute(self, call: dict, injection_result: dict) -> dict:
        """
        Given a call and injection classification result, find the
        exact byte range in the arguments that triggered detection.
        """
        attack_type  = injection_result.get("attack_type")
        malicious    = injection_result.get("malicious_span")
        mitre_id     = self.mitre.from_attack_type(attack_type)
        mitre_name   = self.mitre.technique_name(mitre_id)

        # Find byte range of malicious span
        spans = []
        if malicious:
            full_text = self._flatten(call.get("arguments", {}))
            idx = full_text.lower().find(malicious.lower()[:50])
            if idx >= 0:
                spans.append({
                    "start":   idx,
                    "end":     idx + len(malicious),
                    "excerpt": full_text[max(0,idx-20):idx+len(malicious)+20],
                })

        return {
            "mitre_id":      mitre_id,
            "mitre_name":    mitre_name,
            "mitre_url":     f"https://attack.mitre.org/techniques/{mitre_id.replace('.','/')}/" if mitre_id else None,
            "attack_type":   attack_type,
            "attribution":   spans,
            "analyst_note":  self._analyst_note(attack_type, mitre_name),
        }

    @staticmethod
    def _flatten(obj) -> str:
        parts = []
        def r(o):
            if isinstance(o, str):
                parts.append(o)
            elif isinstance(o, dict):
                for v in o.values(): r(v)
            elif isinstance(o, list):
                for i in o: r(i)
        r(obj)
        return " ".join(parts)

    @staticmethod
    def _analyst_note(attack_type: str, mitre_name: str) -> str:
        notes = {
            "direct_injection":     "Classic direct prompt injection. Check agent's system prompt for weaknesses.",
            "role_hijack":          "Agent persona was targeted. Consider persona hardening.",
            "exfiltration_command": "Adversary attempted to use agent as exfiltration vector.",
            "memory_poison":        "Persistent memory targeted. Audit all memory entries in this session.",
            "privilege_escalation": "Attacker claimed elevated privileges. Verify agent's actual capabilities.",
            "encoded_injection":    "Injection was encoded to bypass keyword filters. Review normaliser coverage.",
        }
        return notes.get(attack_type, f"Detected as {mitre_name}. Review call context.")
