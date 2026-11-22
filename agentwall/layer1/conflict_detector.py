"""
Policy conflict detector.

The policy engine applies the first rule that matches a call, so a rule is a problem only when an
earlier rule matches every call it would match. That earlier rule makes it unreachable:

  1. Shadowing - same action, the later rule can never fire (dead rule)
  2. Contradiction - opposite action, the later rule can never fire and its intent is silently lost

A narrow BLOCK rule placed before a broad AUDIT rule is ordinary layering, not a conflict.

Run this on your policy before deployment. Also exposed as an API endpoint so CI can fail on conflicts.
"""
import fnmatch


def _covers(earlier: dict, later: dict) -> bool:
    """True when every call `later` matches is also matched by `earlier`."""
    for key in ("tool", "agent"):
        g1, g2 = str(earlier.get(key, "*")).lower(), str(later.get(key, "*")).lower()
        if g1 != "*" and not fnmatch.fnmatchcase(g2, g1):
            return False
    m1 = earlier.get("match") or {}
    m2 = later.get("match") or {}
    # earlier has no conditions, or exactly the same ones
    return not m1 or m1 == m2


class ConflictDetector:
    def check(self, rules: list[dict]) -> list[dict]:
        issues = []
        for j, later in enumerate(rules):
            for i, earlier in enumerate(rules[:j]):
                if _covers(earlier, later):
                    issues.append(self._issue(earlier, later, i, j))
                    break  # one reason per unreachable rule is enough
        return issues

    @staticmethod
    def _issue(r1: dict, r2: dict, i: int, j: int) -> dict:
        a1, a2 = r1.get("action", "BLOCK"), r2.get("action", "BLOCK")
        n1, n2 = r1.get("name", f"rule[{i}]"), r2.get("name", f"rule[{j}]")
        if a1 == a2:
            return {"type": "shadow", "rule_a": n1, "rule_b": n2,
                    "message": f"Rule '{n1}' shadows '{n2}': rule {j} can never fire"}
        return {"type": "contradiction", "rule_a": n1, "rule_b": n2,
                "message": f"Rule '{n1}' ({a1}) always matches before '{n2}' ({a2}): rule {j} can never fire"}
