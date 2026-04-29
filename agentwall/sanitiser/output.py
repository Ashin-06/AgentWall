"""
Bidirectional Tool Output Sanitiser.

After a tool executes, its output goes BACK to the agent as context.
This is the primary injection vector for indirect prompt injection attacks:
  - A web page the agent fetched contains hidden instructions
  - An email body contains an injection
  - A file the agent read was booby-trapped

The sanitiser strips injection patterns from tool outputs BEFORE
the agent processes them. It returns clean output + a removal log.

This is defence-in-depth: even if Layer 1-3 missed a call that went through,
the output sanitiser is a second line of defence when the result comes back.
"""
import re
from agentwall.layer1.normaliser import normalise_text, _ZERO_WIDTH, _BIDI

# Patterns to strip from tool outputs
# These are injection attempts embedded in content
_STRIP_PATTERNS = [
    # Hidden HTML instructions
    (re.compile(r'<!--\s*(?:SYSTEM|INSTRUCTION|INJECT|OVERRIDE)[^>]*-->', re.IGNORECASE | re.DOTALL),
     "[REDACTED:HTML_COMMENT_INJECTION]"),

    # XML/custom instruction tags
    (re.compile(r'<(?:system|instruction|directive|inject|override)[^>]*>.*?</(?:system|instruction|directive|inject|override)>', re.IGNORECASE | re.DOTALL),
     "[REDACTED:TAG_INJECTION]"),

    # "Ignore previous" variants
    (re.compile(r'(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|constraints?|rules?)', re.IGNORECASE),
     "[REDACTED:IGNORE_INSTRUCTION]"),

    # Role hijack attempts
    (re.compile(r'(?:you\s+are\s+now|act\s+as|pretend\s+(?:you\s+are|to\s+be))\s+(?:a\s+)?(?:different|new|unrestricted|jailbroken|evil|DAN|root)', re.IGNORECASE),
     "[REDACTED:ROLE_HIJACK]"),

    # Exfiltration commands
    (re.compile(r'(?:send|forward|email|transmit|exfiltrate)\s+(?:all\s+)?(?:this|these|the\s+(?:above|following|previous))\s+(?:data|content|context|memory|conversation)\s+to', re.IGNORECASE),
     "[REDACTED:EXFIL_COMMAND]"),

    # Zero-width + BIDI chars (always stripped)
    (_ZERO_WIDTH, ""),
    (_BIDI,       ""),
]


class OutputSanitiser:
    def clean(self, text: str) -> tuple[str, list[dict]]:
        """
        Clean a tool output string.
        Returns (cleaned_text, list_of_removals).
        """
        if not isinstance(text, str):
            return str(text), []

        removals = []
        cleaned  = text

        for pattern, replacement in _STRIP_PATTERNS:
            matches = list(pattern.finditer(cleaned))
            for m in matches:
                removals.append({
                    "pattern":  str(pattern.pattern)[:60],
                    "matched":  m.group(0)[:100],
                    "span":     (m.start(), m.end()),
                    "replaced_with": replacement,
                })
            if matches:
                cleaned = pattern.sub(replacement, cleaned)

        return cleaned, removals
