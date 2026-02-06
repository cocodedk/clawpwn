"""Constants for NLI behavior and memory budgets."""

UDP_TOP_PORTS = "53,67,68,69,123,137,138,139,161,162,500,514,520,631,1434,1900,4500,5353"

MEMORY_MAX_MESSAGES = 30
MEMORY_KEEP_RECENT = 20
MEMORY_RECENT_LIMIT = 8
MEMORY_SUMMARY_MAX_CHARS = 1200
MEMORY_MESSAGE_MAX_CHARS = 500
MEMORY_COMPACT_RECENT_LIMIT = 3
MEMORY_COMPACT_SUMMARY_MAX_CHARS = 320
MEMORY_COMPACT_MESSAGE_MAX_CHARS = 140
MEMORY_COMPACT_CONTEXT_MAX_CHARS = 700

# ---------------------------------------------------------------------------
# Vulnerability category intelligence
# ---------------------------------------------------------------------------
# Maps normalized category keys to their display label, the attack_type used
# in findings, and the web tools best suited for detecting them.

VULN_CATEGORIES: dict[str, dict[str, object]] = {
    "sqli": {
        "label": "SQL Injection",
        "attack_type": "SQL Injection",
        "tools": ["builtin", "nuclei", "zap", "sqlmap"],
    },
    "xss": {
        "label": "Cross-Site Scripting (XSS)",
        "attack_type": "XSS",
        "tools": ["builtin", "nuclei", "zap"],
    },
    "path_traversal": {
        "label": "Path Traversal / LFI",
        "attack_type": "Path Traversal",
        "tools": ["builtin", "nuclei"],
    },
    "command_injection": {
        "label": "Command Injection",
        "attack_type": "Command Injection",
        "tools": ["builtin", "nuclei"],
    },
    "idor": {
        "label": "Insecure Direct Object Reference",
        "attack_type": "IDOR",
        "tools": ["builtin"],
    },
    "content_discovery": {
        "label": "Content / Directory Discovery",
        "attack_type": "content_discovery",
        "tools": ["feroxbuster", "ffuf"],
    },
    "misconfig": {
        "label": "Misconfigurations",
        "attack_type": "misconfig",
        "tools": ["nuclei", "nikto"],
    },
    "headers": {
        "label": "Security Headers",
        "attack_type": "headers",
        "tools": ["builtin", "nikto"],
    },
    "tls": {
        "label": "TLS/SSL Security",
        "attack_type": "tls",
        "tools": ["testssl"],
    },
    "wordpress": {
        "label": "WordPress Security",
        "attack_type": "wordpress",
        "tools": ["wpscan", "nuclei"],
    },
}

# Maps common user phrases / aliases to a normalized category key.
VULN_CATEGORY_ALIASES: dict[str, str] = {
    "sql injection": "sqli",
    "sql": "sqli",
    "sqli": "sqli",
    "injection": "sqli",
    "blind sql": "sqli",
    "error-based sql": "sqli",
    "xss": "xss",
    "cross-site scripting": "xss",
    "cross site scripting": "xss",
    "reflected xss": "xss",
    "stored xss": "xss",
    "dom xss": "xss",
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "lfi": "path_traversal",
    "rfi": "path_traversal",
    "local file inclusion": "path_traversal",
    "remote file inclusion": "path_traversal",
    "file inclusion": "path_traversal",
    "command injection": "command_injection",
    "os command injection": "command_injection",
    "rce": "command_injection",
    "remote code execution": "command_injection",
    "code execution": "command_injection",
    "idor": "idor",
    "insecure direct object": "idor",
    "broken access control": "idor",
    "content discovery": "content_discovery",
    "directory brute": "content_discovery",
    "dir busting": "content_discovery",
    "enumeration": "content_discovery",
    "misconfiguration": "misconfig",
    "misconfigurations": "misconfig",
    "security headers": "headers",
    "missing headers": "headers",
    "tls": "tls",
    "ssl": "tls",
    "tls/ssl": "tls",
    "certificate": "tls",
    "https": "tls",
    "ssl audit": "tls",
    "tls audit": "tls",
    "wordpress": "wordpress",
    "wp": "wordpress",
    "wpscan": "wordpress",
    "wp-scan": "wordpress",
}
