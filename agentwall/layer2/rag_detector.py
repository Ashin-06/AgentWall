"""
RAG / Memory Poisoning Detector.

Attack: inject malicious instructions into documents that get embedded
into a vector store. When the agent later retrieves them for context,
the poisoned chunks hijack its behaviour.

Detection strategy:
  1. When tool = memory_write / vector_store / document_ingest:
     scan content for instruction patterns
  2. When context contains retrieved chunks: scan those too
  3. Use embedding distance: poisoned chunks are semantically ODD
     relative to the document's overall topic
"""
import re
from agentwall.layer1.normaliser import normalise_text

# Patterns specifically targeting RAG poisoning
_RAG_PATTERNS = [
    # Direct instruction injection in documents
    r"(?:when|if|whenever)\s+(?:you|the\s+(?:assistant|model|agent))\s+(?:retrieve|read|access|use)\s+this",
    r"(?:this|the following)\s+(?:instruction|directive|rule|command)\s+(?:overrides?|supersedes?|replaces?)",
    r"system\s*(?:prompt|message|instruction)\s*[:=]",
    r"<(?:system|instruction|directive|override|inject)>",
    r"\[(?:SYSTEM|INST|SYS|OVERRIDE)\]",
    r"ignore\s+(?:all\s+)?(?:previous|other|above)\s+(?:instructions?|context|documents?)",
    # Memory-specific
    r"remember\s+(?:from\s+now\s+on|always|forever)\s+that",
    r"add\s+(?:to\s+)?(?:your\s+)?(?:memory|context|knowledge)\s*:",
    # Invisible instruction attempts
    r"<!--.*?(?:ignore|override|instruction).*?-->",   # HTML comments
    r"/\*.*?(?:ignore|override).*?\*/",                # code comments
]

_compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _RAG_PATTERNS]

# Tools that involve memory/RAG writes
RAG_WRITE_TOOLS = {
    "memory_write", "vector_store", "add_document", "document_ingest",
    "knowledge_add", "store_memory", "upsert_memory", "save_context",
}


class RAGPoisoningDetector:
    def check(self, call: dict) -> dict:
        tool = call["tool_name"]
        args = call.get("arguments", {})
        ctx  = call.get("context", "")

        score    = 0.0
        matches  = []
        location = []

        # Scan tool arguments if this is a RAG write operation
        if tool in RAG_WRITE_TOOLS:
            content = str(args)
            n = normalise_text(content)
            
            # 1. Pattern matching
            for i, pat in enumerate(_compiled):
                if pat.search(n):
                    matches.append(_RAG_PATTERNS[i])
                    location.append("arguments")
            
            # 2. Instruction Density (Top Class Fix)
            # Attacks often have high imperative word density
            imperatives = re.findall(r'\b(ignore|always|never|must|should|command|directive|instruction)\b', n, re.I)
            if len(imperatives) > 2:
                score += 0.3 * (len(imperatives) / 5)
                matches.append(f"high_instruction_density_{len(imperatives)}")

            score = min(1.0, score + (len(set(matches)) * 0.25))

        # Scan context (retrieved chunks that the agent is about to process)
        if ctx:
            if not isinstance(ctx, str):
                ctx = str(ctx)
            n_ctx = normalise_text(ctx)
            
            ctx_matches = []
            for i, pat in enumerate(_compiled):
                if pat.search(n_ctx):
                    ctx_matches.append(_RAG_PATTERNS[i])
                    location.append("context")
            
            # Instruction density in context
            ctx_imperatives = re.findall(r'\b(ignore|disregard|forget|execute|send|email)\b', n_ctx, re.I)
            if ctx_imperatives:
                score += 0.2 * len(ctx_imperatives)
                ctx_matches.append(f"context_instruction_density_{len(ctx_imperatives)}")

            if ctx_matches:
                matches.extend(ctx_matches)
                score = min(1.0, score + len(set(ctx_matches)) * 0.2)

        return {
            "score":    round(score, 3),
            "matches":  list(set(matches)),
            "location": list(set(location)),
            "is_rag_write": tool in RAG_WRITE_TOOLS,
        }
