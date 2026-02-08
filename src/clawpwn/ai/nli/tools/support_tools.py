"""Tool schemas for support operations (status, target, help, availability, suggestions)."""

from typing import Any

CHECK_STATUS_TOOL: dict[str, Any] = {
    "name": "check_status",
    "description": (
        "Show current project status — findings, phase, target info. "
        "Use when the user asks about status, results, or what has been found."
    ),
    "input_schema": {
        "type": "object",
        "properties": {},
    },
}

SET_TARGET_TOOL: dict[str, Any] = {
    "name": "set_target",
    "description": "Set the active target URL or IP for the project.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL or IP address.",
            },
        },
        "required": ["target"],
    },
}

RESEARCH_VULNERABILITIES_TOOL: dict[str, Any] = {
    "name": "research_vulnerabilities",
    "description": (
        "Look up known CVEs and exploits for a service name and version. "
        "Use when the user wants to research vulnerabilities for a specific technology."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "service": {
                "type": "string",
                "description": "Service or software name (e.g. 'Apache', 'phpMyAdmin').",
            },
            "version": {
                "type": "string",
                "description": "Version string (e.g. '2.4.49', '5.1.0').",
            },
        },
        "required": ["service"],
    },
}

SHOW_HELP_TOOL: dict[str, Any] = {
    "name": "show_help",
    "description": "Show help documentation for a ClawPwn capability or topic.",
    "input_schema": {
        "type": "object",
        "properties": {
            "topic": {
                "type": "string",
                "description": (
                    "Help topic: scan, target, status, recon, exploit, "
                    "killchain, report, lan, permissions, workflow, logs."
                ),
            },
        },
        "required": ["topic"],
    },
}

CHECK_AVAILABLE_TOOLS_TOOL: dict[str, Any] = {
    "name": "check_available_tools",
    "description": (
        "Check which external security tools are installed on the system and which "
        "are missing. Returns install instructions for missing tools. "
        "Call this when you need to verify tool availability before recommending them."
    ),
    "input_schema": {
        "type": "object",
        "properties": {},
    },
}

SUGGEST_TOOLS_TOOL: dict[str, Any] = {
    "name": "suggest_tools",
    "description": (
        "Recommend external security tools that would be valuable for the current "
        "target or task, including tools ClawPwn does not have built-in plugins for. "
        "Use your knowledge of the security tooling ecosystem. Examples: gobuster for "
        "directories, jwt_tool for JWT attacks, responder for LLMNR/NBT-NS poisoning, "
        "impacket for Windows protocols, etc. "
        "Note: credential_test can run with tool=hydra when hydra is installed. "
        "Also, sqlmap, wpscan, and testssl are built-in plugins — use web_scan "
        "with the appropriate tool name instead of suggesting them. "
        "Always include install commands and practical usage examples for the "
        "current target."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "suggestions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Tool name (e.g. 'sqlmap').",
                        },
                        "reason": {
                            "type": "string",
                            "description": "Why this tool is recommended.",
                        },
                        "install_command": {
                            "type": "string",
                            "description": "Shell command to install (e.g. 'sudo apt install sqlmap').",
                        },
                        "example_usage": {
                            "type": "string",
                            "description": (
                                "Practical command example against the current target."
                            ),
                        },
                    },
                    "required": ["name", "reason", "install_command", "example_usage"],
                },
                "description": "List of recommended tools with install and usage info.",
            },
        },
        "required": ["suggestions"],
    },
}

LIST_RECENT_ARTIFACTS_TOOL: dict[str, Any] = {
    "name": "list_recent_artifacts",
    "description": (
        "List recently created project artifacts such as custom scripts, evidence files, "
        "and generated reports. Use when the user asks where a script/file was saved."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "enum": ["all", "scripts", "evidence", "reports"],
                "description": "Optional artifact category filter. Default: all.",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum items to return. Default: 5.",
            },
        },
    },
}
