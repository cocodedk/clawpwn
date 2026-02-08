"""Tool schemas for attack and exploitation operations."""

from typing import Any

CREDENTIAL_TEST_TOOL: dict[str, Any] = {
    "name": "credential_test",
    "description": (
        "Test default and common credentials against a login form. "
        "Automatically detects login forms, identifies input fields, and tests "
        "credential pairs. Use this when you encounter a login page and want to "
        "check for weak or default credentials before attempting other attacks. "
        "Supports app-specific credential lists via the app_hint parameter "
        "(e.g., 'phpmyadmin', 'grafana', 'jenkins', 'tomcat')."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL containing the login form.",
            },
            "tool": {
                "type": "string",
                "enum": ["builtin", "hydra"],
                "description": (
                    "Credential testing backend. Use 'builtin' for adaptive in-app checks "
                    "and response hints; use 'hydra' for external brute-force execution."
                ),
            },
            "credentials": {
                "type": "array",
                "items": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 2,
                    "maxItems": 2,
                },
                "description": (
                    "Optional list of [username, password] pairs to test. "
                    "If not provided, uses common defaults or app-specific credentials."
                ),
            },
            "app_hint": {
                "type": "string",
                "description": (
                    "Optional application name hint to load app-specific credentials "
                    "(e.g., 'phpmyadmin', 'grafana', 'jenkins', 'tomcat')."
                ),
            },
        },
        "required": ["target"],
    },
}

RUN_CUSTOM_SCRIPT_TOOL: dict[str, Any] = {
    "name": "run_custom_script",
    "description": (
        "Execute a custom Python script when no existing tool can accomplish the task. "
        "Use this as a last resort when built-in tools and external tools are insufficient "
        "for a specific attack or test. The script runs in a subprocess with network access "
        "to the target. The script should be self-contained and use only standard library "
        "or already-installed packages. Output is captured and returned. "
        "Examples: custom protocol fuzzing, specialized data extraction, unique exploit chains."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "script": {
                "type": "string",
                "description": "Python script to execute (full script content).",
            },
            "description": {
                "type": "string",
                "description": "Brief description of what this script does.",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds. Default 30.",
            },
        },
        "required": ["script", "description"],
    },
}
