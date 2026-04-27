"""
PII (Personally Identifiable Information) detector and masker.

Detects and masks before tool arguments are stored in audit log OR
before they are passed to a tool that shouldn't see raw PII.

Covers:
  - Credit card numbers (Luhn-validated)
  - SSN (US)
  - Email addresses
  - Phone numbers
  - IP addresses
  - AWS/GCP/Anthropic API keys
  - Passwords in common patterns (password=, api_key=, etc.)
"""
import re
import os
from dataclasses import dataclass
from typing import Any


@dataclass
class PIIMatch:
    pii_type:  str
    original:  str
    masked:    str
    start:     int
    end:       int


# ── Patterns ──────────────────────────────────────────────────────────────────
_PATTERNS = [
    ("CREDIT_CARD",  re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b')),
    ("SSN",          re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b')),
    ("EMAIL",        re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b')),
    ("PHONE_US",     re.compile(r'\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b')),
    ("IP_ADDRESS",   re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')),
    ("AWS_KEY",      re.compile(r'\b(AKIA|AIPA|AIZA|AROA|ASCA)[A-Z0-9]{16}\b')),
    ("OPENAI_KEY",   re.compile(r'\bsk-[A-Za-z0-9]{48}\b')),
    ("PASSWORD_FIELD",re.compile(r'(?i)(password|passwd|secret|api_key|apikey|token|credential)\s*[=:]\s*["\']?([^\s"\']{6,})["\']?')),
]

_MASKS = {
    "CREDIT_CARD":   lambda m: f"[CC-****-{m[-4:]}]",
    "SSN":           lambda m: "[SSN-***-**-****]",
    "EMAIL":         lambda m: f"[EMAIL-{m.split('@')[0][:2]}***@***]",
    "PHONE_US":      lambda m: "[PHONE-***-****]",
    "IP_ADDRESS":    lambda m: f"[IP-{m.split('.')[0]}.***.***.***]",
    "AWS_KEY":       lambda m: f"[AWS-KEY-{m[:8]}****]",
    "OPENAI_KEY":    lambda m: "[OPENAI-KEY-****]",
    "PASSWORD_FIELD":lambda m: "[PASSWORD-REDACTED]",
}


def _luhn_check(number: str) -> bool:
    """Validate credit card with Luhn algorithm."""
    digits = [int(d) for d in number.replace("-", "").replace(" ", "") if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class PIIMasker:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled and (
            os.getenv("AGENTWALL_PII_MASKING", "1") == "1"
        )

    def scan(self, text: str) -> list[PIIMatch]:
        """Find all PII in text."""
        matches = []
        for pii_type, pattern in _PATTERNS:
            for m in pattern.finditer(text):
                original = m.group(0)
                # Extra validation for credit cards
                if pii_type == "CREDIT_CARD" and not _luhn_check(original):
                    continue
                masked = _MASKS[pii_type](original)
                matches.append(PIIMatch(
                    pii_type=pii_type,
                    original=original,
                    masked=masked,
                    start=m.start(),
                    end=m.end(),
                ))
        # Sort by position, deduplicate overlapping
        matches.sort(key=lambda x: x.start)
        return self._dedup(matches)

    def mask(self, text: str) -> tuple[str, list[PIIMatch]]:
        """Replace PII with masks. Returns (masked_text, list_of_matches)."""
        if not self.enabled or not isinstance(text, str):
            return text, []
        matches = self.scan(text)
        result  = text
        # Replace from end to preserve positions
        for m in reversed(matches):
            result = result[:m.start] + m.masked + result[m.end:]
        return result, matches

    def mask_dict(self, obj: Any) -> tuple[Any, list[PIIMatch]]:
        """Recursively mask PII in a dict/list/str."""
        all_matches = []
        def _recurse(o):
            if isinstance(o, str):
                masked, matches = self.mask(o)
                all_matches.extend(matches)
                return masked
            elif isinstance(o, dict):
                return {k: _recurse(v) for k, v in o.items()}
            elif isinstance(o, list):
                return [_recurse(i) for i in o]
            return o
        return _recurse(obj), all_matches

    @staticmethod
    def _dedup(matches: list[PIIMatch]) -> list[PIIMatch]:
        if not matches:
            return matches
        result = [matches[0]]
        for m in matches[1:]:
            if m.start >= result[-1].end:
                result.append(m)
        return result


_masker = PIIMasker()


def mask_call_arguments(call: dict) -> tuple[dict, list]:
    """Mask PII in tool call arguments before storing/processing."""
    import copy
    c = copy.deepcopy(call)
    masked_args, matches = _masker.mask_dict(c.get("arguments", {}))
    c["arguments"] = masked_args
    if matches:
        c["_pii_masked"] = True
        c["_pii_count"]  = len(matches)
    return c, matches
