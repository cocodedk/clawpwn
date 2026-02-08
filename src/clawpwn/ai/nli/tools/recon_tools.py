"""Tool schemas for reconnaissance and research operations."""

from typing import Any

WEB_SEARCH_TOOL: dict[str, Any] = {
    "name": "web_search",
    "description": (
        "Search the internet for security research, exploit techniques, default "
        "credentials, configuration weaknesses, or attack methodologies for a target "
        "technology. Use when you need information beyond the CVE database — e.g. "
        "default creds, known misconfigs, pentest cheatsheets, or community-discovered "
        "attack paths. Examples: 'phpMyAdmin default credentials exploit', "
        "'Grafana 8.3.0 vulnerabilities', 'Jenkins pentesting techniques'."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search query (e.g. 'phpMyAdmin default credentials exploit').",
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum results to return. Default 5.",
            },
        },
        "required": ["query"],
    },
}

FINGERPRINT_TARGET_TOOL: dict[str, Any] = {
    "name": "fingerprint_target",
    "description": (
        "Perform reconnaissance on a web target: fetch HTTP headers, identify server "
        "software and versions, check for exposed configuration pages, default "
        "credentials pages, robots.txt, technology fingerprints, and common admin "
        "paths. Use this BEFORE scanning to understand what you're attacking and "
        "plan the best strategy. Returns server stack, identified technologies, "
        "version hints, exposed paths, and missing security headers."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL to fingerprint (e.g. http://192.168.1.10/phpMyAdmin/).",
            },
        },
        "required": ["target"],
    },
}
