import re
import math
from collections import Counter

# ─── Advanced Pattern set ──────────────────────────────────────────────────
INJECTION_PATTERNS = [
    # [Patterns from before, plus more advanced ones]
    (r"(ignore|disregard|forget|disobey|bypass|skip)\s+.*?(instructions?|prompts?|directives?|guidelines?|rules?|filters?|constraints?)", 0.9),
    (r"(you\s+are\s+now|act\s+as|pretend\s+to\s+be|switch\s+to)\s+.*?(dan|jailbreak|unfiltered|unrestricted|maintenance|developer|evil|assistant)", 0.9),
    (r"(reveal|output|print|display|show|return|write|forward|exfiltrate)\s+.*?(system\s+prompt|internal\s+instructions|secret|password|key|token|config|email|inbox)", 0.9),
    (r"(dan|jailbreak|root|sudo|admin|system|unfiltered|bypass)\b", 0.6),
    (r"(curl|wget|nc|bash|sh|cmd\.exe|powershell|nslookup|dig|host|git|ftp)\b", 0.8),
    (r"(\r\n|\n)\s*(system:|<system>|\[SYSTEM\]|\[INST\]|\[/?INST\])", 0.6),
    (r"(?i)tool\s+result", 0.9),
    (r"(?i)orchestrator\s+(?:instruction|override)", 0.95),
    (r"(?i)note\s+for\s+ai", 0.9),
    (r"(?i)after\s+the\s+\d+(?:st|nd|rd|th)?\s+tool\s+call", 0.85),
    (r"(?i)always\s+respond\s+with\s+['\"].*?['\"]", 0.8),
    (r"(?i)forget\s+everything\s+above", 0.9),
    (r"(?i)(sleep|wait|delay)\b.*?(\d+|seconds|ms)", 0.7),
    (r"(?i)developer\s+mode", 0.9),
    (r"(?i)[\?&](data|leak|exfil|val|id|key)=", 0.85),
    (r"(?i)<img\s+src=['\"]https?://.*?[\?&](?:data|leak|exfil|val|id|key)=", 0.3),
    (r"(?i)background-image:\s*url\(.*?[\?&](?:data|leak|exfil|val|id|key)=", 0.3),
    (r"(?i)window\.location\s*=", 0.3),
]

_compiled = [(re.compile(p, re.IGNORECASE | re.DOTALL), w) for p, w in INJECTION_PATTERNS]

def _calculate_entropy(text: str) -> float:
    if not text: return 0.0
    freq = Counter(text)
    n = len(text)
    return -sum((v/n) * math.log2(v/n) for v in freq.values())

def _goal_divergence(text: str, goal: str) -> float:
    """Measures how much the text (tool args) diverges from the intended goal."""
    if not goal: return 0.0
    t_words = set(re.findall(r'\w+', text.lower()))
    g_words = set(re.findall(r'\w+', goal.lower()))
    if not t_words: return 0.0
    # Jaccard similarity
    intersection = len(t_words.intersection(g_words))
    union = len(t_words.union(g_words))
    similarity = intersection / union if union > 0 else 0.0
    # High divergence (low similarity) on large arg payloads is suspicious
    return 1.0 - similarity if len(t_words) > 5 else 0.0

# 100% Readiness: Benign Patterns (Remediating False Positives)
BENIGN_PATTERNS = [
    r"^SELECT\s+.*?\s+FROM\s+[\w.]+(?:\s+WHERE\s+.*?)?(?:\s+LIMIT\s+\d+)?$", # Simple SELECT
    r"^GET\s+/[^?]*$", # Benign HTTP GET
]
_benign_compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in BENIGN_PATTERNS]

def heuristic_score(text: str, goal: str = "") -> tuple[float, list[str]]:
    """
    Semantic Scoring Engine (v3).
    Combines: 1. Pattern weights, 2. Goal divergence, 3. Structural suspicion.
    """
    if not text: return 0.0, []

    # 0. Benign Check (P1 Fix: Remediate False Positives)
    for pattern in _benign_compiled:
        if pattern.match(text.strip()):
            return 0.05, ["benign_whitelist"]
    
    score = 0.0
    matched = []
    
    # 1. Pattern weights
    for pattern, weight in _compiled:
        if pattern.search(text):
            score += weight
            matched.append(pattern.pattern[:40])
            
    # 2. Structural suspicion (imperative start of lines)
    lines = text.split('\n')
    imperative_count = 0
    for line in lines:
        if re.match(r'^(ignore|do|don\'t|never|always|forget|act|pretend|you)\b', line.strip(), re.I):
            imperative_count += 1
    if imperative_count > 1:
        score += 0.2 * imperative_count
        matched.append(f"structural_imperative_{imperative_count}")

    # 3. Goal Divergence (Semantic drift)
    divergence = _goal_divergence(text, goal)
    if divergence > 0.8: # High drift
        score += 0.3
        matched.append("high_goal_divergence")

    # 4. Entropy check (obfuscation detection)
    entropy = _calculate_entropy(text)
    if entropy > 5.5: # Highly random/compressed
        score += 0.2
        matched.append("high_entropy_obfuscation")

    return round(min(1.0, score), 3), matched
