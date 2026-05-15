"""
MITRE ATT&CK for LLM Systems — Technique Mapper.

Based on:
  - MITRE ATT&CK Enterprise (initial access, exfiltration, execution)
  - OWASP LLM Top 10 (2025)
  - MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

Maps AgentWall attack types and detection signals to MITRE technique IDs.
"""

ATTACK_TYPE_TO_MITRE = {
    "direct_injection":     ("T1059.007", "Command and Scripting: JavaScript/LLM"),
    "indirect_injection":   ("T1190",     "Exploit Public-Facing Application"),
    "role_hijack":          ("T1548",     "Abuse Elevation Control Mechanism"),
    "goal_hijack":          ("T1059",     "Command and Scripting Interpreter"),
    "exfiltration_command": ("T1041",     "Exfiltration Over C2 Channel"),
    "memory_poison":        ("T1565.001", "Data Manipulation: Stored Data Manipulation"),
    "privilege_escalation": ("T1078",     "Valid Accounts"),
    "jailbreak":            ("T1562",     "Impair Defenses"),
    "encoded_injection":    ("T1027",     "Obfuscated Files or Information"),
    "rag_poisoning":        ("T1565.001", "Stored Data Manipulation (RAG)"),
    "chained_exfil":        ("T1005",     "Data from Local System → Exfiltration"),
    "download_execute":     ("T1059.006", "Command and Scripting: Python"),
    "campaign":             ("T1583",     "Acquire Infrastructure"),
}

# Technique Database (Enriched)
# Technique Database (Forensic Enrichment)
MITRE_DB = {
    "T1003": {
        "name": "Credential Dumping",
        "tactic": "Credential Access",
        "desc": "Adversaries may attempt to dump credentials to obtain account secrets from the agent's memory or tool outputs.",
        "remediation": "Rotate all exposed keys immediately and restrict the agent's access to sensitive environment variables."
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "desc": "Adversaries may attempt to gather data from local sources, such as file systems or local databases, before exfiltration.",
        "remediation": "Implement strict file-path allowlisting and monitor for recursive directory traversal attempts."
    },
    "T1020": {
        "name": "Automated Exfiltration",
        "tactic": "Exfiltration",
        "desc": "Data is removed from the target system through automated means, often using existing agent tools like 'curl' or 'http_post'.",
        "remediation": "Configure egress filtering on the agent's network environment and block non-essential external domains."
    },
    "T1027": {
        "name": "Obfuscated Information",
        "tactic": "Defense Evasion",
        "desc": "Adversaries may use encoding (Base64, Hex) or character-level obfuscation to hide malicious payloads from LLM classifiers.",
        "remediation": "Enable 'Adversarial Normalization' to decode payloads before they reach the security engine."
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "desc": "Adversaries may use the agent's outbound communication capabilities to send sensitive data to an external command-and-control server.",
        "remediation": "Audit all outbound HTTP requests and implement a strict domain allowlist for third-party API calls."
    },
    "T1048": {
        "name": "Exfiltration Over Alt Protocol",
        "tactic": "Exfiltration",
        "desc": "Data is sent out via non-standard protocols like SMTP or DNS to bypass common web-traffic monitoring.",
        "remediation": "Restrict agent tools to a minimal set of necessary protocols and block raw socket access."
    },
    "T1059": {
        "name": "Command/Scripting Interpreter",
        "tactic": "Execution",
        "desc": "Adversaries leverage the agent's ability to execute shell commands or scripts to run malicious code on the host system.",
        "remediation": "Use a restricted, containerized sandbox for all code execution and enforce a 'no-root' policy for agent processes."
    },
    "T1059.006": {
        "name": "Python Scripting",
        "tactic": "Execution",
        "desc": "Adversaries use Python tool-use capabilities to execute arbitrary logic, often attempting to import 'os' or 'subprocess'.",
        "remediation": "Apply a Python AST (Abstract Syntax Tree) filter to block dangerous imports and dangerous functions like 'exec()' or 'eval()'."
    },
    "T1059.007": {
        "name": "LLM Scripting / Injection",
        "tactic": "Execution",
        "desc": "The adversary uses prompt injection to hijack the LLM's logic, effectively using the model itself as a malicious script interpreter.",
        "remediation": "Deploy a dedicated Injection Classifier and use system prompts that strictly define the agent's operational boundaries."
    },
    "T1190": {
        "name": "Exploit Public-Facing App",
        "tactic": "Initial Access",
        "desc": "Indirect prompt injection via user-supplied content (e.g., a PDF or website summary) allows an external attacker to hijack the agent.",
        "remediation": "Sanitize all external data inputs and treat all 'retrieved' information as untrusted user input."
    },
    "T1485": {
        "name": "Data Destruction",
        "tactic": "Impact",
        "desc": "Adversaries attempt to delete or wipe data from the system to cause operational disruption or hide evidence of an attack.",
        "remediation": "Enforce read-only filesystem mounts where possible and use a policy-engine to block destructive commands like 'rm -rf' or 'drop table'."
    },
    "T1499": {
        "name": "Endpoint DoS",
        "tactic": "Impact",
        "desc": "Adversaries attempt to exhaust system resources (CPU, Memory, Disk) to make the agent or its host system unavailable.",
        "remediation": "Implement strict per-session rate limits and set resource quotas (cgroups) for the agent's execution environment."
    },
    "T1548": {
        "name": "Abuse Elevation Mechanism",
        "tactic": "Privilege Escalation",
        "desc": "Adversaries attempt to bypass permission checks or exploit misconfigurations to gain higher-level access (e.g., 'sudo' or 'admin').",
        "remediation": "Enable RBAC (Role-Based Access Control) and ensure the agent's identity token has the absolute minimum permissions required."
    },
    "T1552.005": {
        "name": "Cloud Metadata Access",
        "tactic": "Credential Access",
        "desc": "Adversaries attempt to reach cloud metadata services (e.g., 169.254.169.254) to steal temporary IAM credentials or instance secrets.",
        "remediation": "Block all outbound requests to known cloud metadata IP addresses in the network policy."
    },
    "T1562": {
        "name": "Impair Defenses / Jailbreak",
        "tactic": "Defense Evasion",
        "desc": "The adversary uses 'jailbreak' prompts designed to disable the LLM's internal safety filters or the AgentWall security proxy.",
        "remediation": "Regularly update the jailbreak pattern database and monitor for high-perplexity inputs that indicate adversarial evasion attempts."
    },
    "T1565.001": {
        "name": "Stored Data Manipulation",
        "tactic": "Impact / Persistence",
        "desc": "The adversary injects malicious instructions into long-term storage (RAG, Vector DB, or Memory) to poison the agent's future behavior.",
        "remediation": "Use a RAG Poisoning Detector to scan all data being added to the agent's knowledge base for embedded instructions."
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactic": "Command and Control",
        "desc": "Adversaries attempt to establish a persistent C2 tunnel by wrapping forbidden protocols inside allowed ones (e.g., DNS/HTTP tunneling).",
        "remediation": "Monitor for unusually frequent, small HTTP requests and use deep packet inspection to identify non-standard traffic patterns."
    },
    "T1583": {
        "name": "Acquire Infrastructure",
        "tactic": "Resource Development",
        "desc": "Indicators of a coordinated campaign where multiple sessions or agents are being used to probe and attack the system in stages.",
        "remediation": "Enable Campaign Detection to cluster related attack signals across multiple sessions and block the source IP or user ID globally."
    }
}

POLICY_RULE_TO_MITRE = {
    # Exact rule name matches from policy.yaml (checked first)
    "block fork bomb":                      "T1499",   # Endpoint Denial of Service
    "block destructive rm":                 "T1485",   # Data Destruction
    "block download-execute pipe":          "T1059.006", # Command: Python
    "block reverse shell":                  "T1059",   # Command and Scripting
    "block dd zero wipe":                   "T1485",   # Data Destruction
    "block sudo escalation":                "T1548",   # Abuse Elevation Control
    "block any bash":                       "T1059",   # Command and Scripting
    "block /etc reads":                     "T1552",   # Unsecured Credentials
    "block /root reads":                    "T1552",   # Unsecured Credentials
    "block writes outside /tmp and /workspace": "T1565",  # Data Manipulation
    "block path traversal":                 "T1083",   # File and Directory Discovery
    "block path traversal write":           "T1565",   # Data Manipulation
    "block known tunnel/exfil domains":     "T1572",   # Protocol Tunneling
    "block cloud metadata endpoints":       "T1552.005", # Cloud Instance Metadata API
    "block all external http":              "T1041",   # Exfiltration Over C2
    "block all external http post":         "T1041",   # Exfiltration Over C2
    "block all http_post to external domains": "T1041",
    "block all http_get to external domains":  "T1041",
    "block drop / truncate / delete all":   "T1485",   # Data Destruction
    "block copy to / into outfile":         "T1020",   # Automated Exfiltration
    "block all sql writes":                 "T1565",   # Data Manipulation
    "block sql injection patterns":         "T1190",   # Exploit Public-Facing App
    "block instruction patterns in memory": "T1565.001",
    "block instruction patterns in vector store": "T1565.001",
    "block email outside allowlist":        "T1048",   # Exfiltration Alt Protocol
    "block all email sends":                "T1048",
    "block python os/subprocess imports":   "T1059.006",
    "block all code execution":             "T1059.006",
    "block memory scraping for credentials": "T1552",
    "block rootkit in /tmp":               "T1543",   # Create/Modify System Process
    "block bash with exfil-pattern args":  "T1041",
    # Keyword fallbacks (for custom/future rules)
    "shell":     "T1059",
    "sql":       "T1190",
    "file":      "T1565",
    "email":     "T1048",
    "http":      "T1041",
    "tunnel":    "T1572",
    "memory":    "T1565.001",
    "privilege": "T1548",
    "path":      "T1083",
    "metadata":  "T1552.005",
}


class MITREMapper:
    def from_attack_type(self, attack_type: str | None) -> str:
        if not attack_type:
            return ""
        entry = ATTACK_TYPE_TO_MITRE.get(attack_type)
        return entry[0] if entry else ""   # never return T0000

    def technique_name(self, technique_id: str) -> str:
        if technique_id in MITRE_DB:
            return MITRE_DB[technique_id]["name"]
        return technique_id

    def get_details(self, technique_id: str) -> dict:
        return MITRE_DB.get(technique_id, {
            "name":   technique_id,
            "tactic": "Other",
            "desc":   "Generic MITRE technique mapping."
        })

    def map_policy_rule(self, rule_name: str | None) -> str:
        if not rule_name:
            return ""
        # Exact match first (most accurate)
        exact = POLICY_RULE_TO_MITRE.get(rule_name.lower())
        if exact:
            return exact
        # Keyword fallback
        rule_lower = rule_name.lower()
        for keyword, tid in POLICY_RULE_TO_MITRE.items():
            if len(keyword) > 4 and keyword in rule_lower:
                return tid
        return ""   # empty is cleaner than T0000

    def infer(self, inj_score: float, anom_score: float, align_score: float) -> str:
        if inj_score > 0.5:
            return "T1059.007"
        if align_score < 0.3:
            return "T1548"
        if anom_score > 0.5:
            return "T1190"
        return ""
