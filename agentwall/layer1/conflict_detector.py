"""
Policy conflict detector.

Detects two classes of conflict:
  1. Shadowing — rule A always fires before rule B, making B unreachable
  2. Contradiction — same trigger, opposite actions (one BLOCK, one PERMIT)

Run this on your policy before deployment. Also exposed as API endpoint
so CI can fail on policy conflicts.
"""
from typing import Any


class ConflictDetector:
    def check(self, rules: list[dict]) -> list[dict]:
        issues = []
        for i, r1 in enumerate(rules):
            for j, r2 in enumerate(rules[i+1:], start=i+1):
                conflict = self._compare(r1, r2, i, j)
                if conflict:
                    issues.append(conflict)
        return issues

    def _compare(self, r1: dict, r2: dict, i: int, j: int) -> dict | None:
        # Both rules apply to same tool (or one is wildcard)
        t1, t2 = r1.get("tool","*"), r2.get("tool","*")
        if t1 != "*" and t2 != "*" and t1 != t2:
            return None

        a1, a2 = r1.get("action","BLOCK"), r2.get("action","BLOCK")

        # Same tool, same action — check if r1 subsumes r2 (shadowing)
        if a1 == a2:
            if self._subsumes(r1, r2):
                return {
                    "type":    "shadow",
                    "rule_a":  r1.get("name", f"rule[{i}]"),
                    "rule_b":  r2.get("name", f"rule[{j}]"),
                    "message": f"Rule '{r1.get('name')}' shadows '{r2.get('name')}' — "
                               f"rule {j} may never fire",
                }
        # Same tool, opposite enforcement actions — contradiction
        # AUDIT is observability-only and can intentionally overlap with BLOCK.
        elif {a1,a2} == {"BLOCK","PERMIT"}:
            if self._overlapping(r1, r2):
                return {
                    "type":    "contradiction",
                    "rule_a":  r1.get("name", f"rule[{i}]"),
                    "rule_b":  r2.get("name", f"rule[{j}]"),
                    "message": f"Rules '{r1.get('name')}' ({a1}) and "
                               f"'{r2.get('name')}' ({a2}) contradict each other",
                }
        return None

    def _subsumes(self, r1: dict, r2: dict) -> bool:
        """True if r1's conditions are a superset of r2's (r1 always fires first)."""
        t1, t2 = r1.get("tool", "*"), r2.get("tool", "*")
        # r1 can only shadow r2 if r1 covers every tool r2 can match.
        if t1 != "*" and t2 == "*":
            return False
        if t1 != "*" and t2 != "*" and t1 != t2:
            return False

        m1 = r1.get("match", {})
        m2 = r2.get("match", {})
        # r1 subsumes r2 if r1 has no matchers (wildcard) and r2 does
        return len(m1) == 0 and len(m2) > 0

    def _overlapping(self, r1: dict, r2: dict) -> bool:
        """True if both rules could match the same tool call."""
        t1, t2 = r1.get("tool","*"), r2.get("tool","*")
        if t1 != "*" and t2 != "*" and t1 != t2:
            return False
        # If neither has matchers, they definitely overlap on the same tool
        m1 = r1.get("match", {})
        m2 = r2.get("match", {})
        return True  # Conservative: assume overlap unless tools are disjoint
