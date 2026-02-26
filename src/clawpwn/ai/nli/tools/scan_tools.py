"""Tool schemas for scanning operations (web scan, network scan, discovery)."""

from typing import Any

WEB_SCAN_TOOL: dict[str, Any] = {
    "name": "web_scan",
    "description": (
        "Scan a web application URL for security vulnerabilities. "
        "Use this when the user provides a URL (http/https) and wants to test it for issues. "
        "When the target is a known application (phpMyAdmin, WordPress, Joomla, Jenkins, "
        "Grafana, etc.), select the most relevant vuln_categories and tools automatically. "
        "For example: phpMyAdmin targets should focus on sqli and misconfig; WordPress "
        "targets should use wpscan and focus on wordpress, xss, sqli, and misconfig; "
        "HTTPS targets needing TLS auditing should use testssl and the tls category. "
        "For deep SQL injection testing, prefer sqlmap over builtin. "
        "Always prefer depth=deep for targeted scans. "
        "The 'builtin' tool is always available. External tools (nuclei, nikto, zap, "
        "feroxbuster, ffuf, searchsploit, sqlmap, wpscan, testssl) may or may not be "
        "installed — "
        "check the system prompt context."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "The target URL to scan (e.g. http://192.168.1.10/phpMyAdmin/).",
            },
            "vuln_categories": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [
                        "sqli",
                        "xss",
                        "path_traversal",
                        "command_injection",
                        "idor",
                        "content_discovery",
                        "misconfig",
                        "headers",
                        "tls",
                        "wordpress",
                    ],
                },
                "description": (
                    "Vulnerability categories to focus on. When omitted, all checks run. "
                    "Set this when the user asks for a specific vulnerability type or "
                    "when the target application implies specific risks."
                ),
            },
            "depth": {
                "type": "string",
                "enum": ["quick", "normal", "deep"],
                "description": "Scan depth. Use 'deep' for targeted/focused scans.",
            },
            "tools": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [
                        "builtin",
                        "nuclei",
                        "feroxbuster",
                        "ffuf",
                        "nikto",
                        "searchsploit",
                        "zap",
                        "sqlmap",
                        "wpscan",
                        "testssl",
                    ],
                },
                "description": (
                    "Which scanner plugins to run. 'builtin' is always available. "
                    "Only include external tools you know are installed."
                ),
            },
            "timeout": {
                "type": "number",
                "description": "Per-tool timeout in seconds. No default — tools run to completion unless specified.",
            },
            "concurrency": {
                "type": "integer",
                "description": "Worker thread count. Default 10.",
            },
        },
        "required": ["target"],
    },
}

NETWORK_SCAN_TOOL: dict[str, Any] = {
    "name": "network_scan",
    "description": (
        "Scan a single host IP for open ports and services. "
        "Use this when the user provides an IP address (not a URL) and wants port scanning. "
        "When the user asks about specific ports (e.g. 'is port 21 open'), "
        "set ports to just those ports and depth=quick. "
        "Defaults: scanner=nmap, depth=deep, verify_tcp=true, verbose=true."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Host IP address to scan (e.g. 192.168.1.10).",
            },
            "scanner": {
                "type": "string",
                "enum": ["nmap", "rustscan", "masscan", "naabu"],
                "description": "Port scanner to use. Default nmap.",
            },
            "depth": {
                "type": "string",
                "enum": ["quick", "normal", "deep"],
                "description": "Scan depth. Default deep.",
            },
            "ports": {
                "type": "string",
                "description": "Port specification (e.g. '80,443', '1-1024', 'all').",
            },
            "udp": {"type": "boolean", "description": "Include UDP scan. Default true."},
            "udp_full": {
                "type": "boolean",
                "description": "Full UDP range (1-65535) instead of top ports.",
            },
            "verify_tcp": {
                "type": "boolean",
                "description": "Verify TCP services. Default true.",
            },
            "parallel": {
                "type": "integer",
                "description": "Parallel port groups. Default 40.",
            },
        },
        "required": ["target"],
    },
}

DISCOVER_HOSTS_TOOL: dict[str, Any] = {
    "name": "discover_hosts",
    "description": (
        "Discover live hosts on a network/subnet. "
        "Use when the user provides a CIDR range (e.g. 192.168.1.0/24) or mentions "
        "LAN/network/subnet discovery."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "network": {
                "type": "string",
                "description": "CIDR range (e.g. 192.168.1.0/24).",
            },
            "scanner": {
                "type": "string",
                "enum": ["nmap", "rustscan", "masscan", "naabu"],
                "description": "Scanner for host discovery. Default nmap.",
            },
            "concurrency": {
                "type": "integer",
                "description": "Max concurrent scans. Default 10.",
            },
            "max_hosts": {
                "type": "integer",
                "description": "Max hosts to scan. Default 256.",
            },
        },
        "required": ["network"],
    },
}
