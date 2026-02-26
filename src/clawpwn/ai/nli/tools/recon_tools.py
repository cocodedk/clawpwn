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

FETCH_URL_TOOL: dict[str, Any] = {
    "name": "fetch_url",
    "description": (
        "Fetch the raw content of a URL and return the response body (HTML, JSON, "
        "or plain text). Unlike fingerprint_target which returns structured recon "
        "data (headers, tech stack), this returns the actual page content for parsing — "
        "e.g. extracting ARNs, tokens, API keys, or hidden data from JavaScript. "
        "Supports GET, POST, PUT, and DELETE methods."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "URL to fetch (e.g. http://example.com/page).",
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE"],
                "description": "HTTP method. Default GET.",
            },
            "headers": {
                "type": "object",
                "description": "Optional HTTP headers as key-value pairs.",
            },
            "body": {
                "type": "string",
                "description": "Optional request body (for POST/PUT). Sent as JSON if parseable, else form data.",
            },
        },
        "required": ["url"],
    },
}
