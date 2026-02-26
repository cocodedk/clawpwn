"""Tool schemas for attack plan management."""

from typing import Any

SAVE_PLAN_TOOL: dict[str, Any] = {
    "name": "save_plan",
    "description": (
        "Save a numbered attack plan for the current target. Call this BEFORE "
        "executing any scans. The plan persists across restarts so the agent can "
        "resume where it left off. Each step must include the tool name so the "
        "system can automatically order steps fastest-first. Steps are reordered "
        "by speed tier: fast tools (fingerprint, research, credential_test) run "
        "before medium tools (builtin, nikto, nuclei) which run before slow "
        "tools (sqlmap, wpscan, testssl, feroxbuster)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "steps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "description": {
                            "type": "string",
                            "description": (
                                "Concise description of what this step does "
                                "(e.g., 'SQL injection deep scan on login form')."
                            ),
                        },
                        "tool": {
                            "type": "string",
                            "enum": [
                                "fingerprint_target",
                                "web_search",
                                "research_vulnerabilities",
                                "credential_test",
                                "web_scan:builtin",
                                "web_scan:nikto",
                                "web_scan:nuclei",
                                "web_scan:sqlmap",
                                "web_scan:wpscan",
                                "web_scan:testssl",
                                "web_scan:feroxbuster",
                                "web_scan:ffuf",
                                "web_scan:zap",
                                "network_scan:quick",
                                "network_scan:deep",
                                "discover_hosts",
                                "credential_test:hydra",
                                "fetch_url",
                                "run_custom_script",
                                "run_command",
                                "suggest_tools",
                            ],
                            "description": (
                                "The ClawPwn tool (and optional variant) this step "
                                "will use. This determines execution order."
                            ),
                        },
                        "target_ports": {
                            "type": "string",
                            "description": (
                                "Port(s) to focus on (e.g. '21', '80,443'). "
                                "Set this when the user asks about specific ports. "
                                "Omit for broad scans."
                            ),
                        },
                    },
                    "required": ["description", "tool"],
                },
                "description": (
                    "List of plan steps. Each step has a description and a tool name. "
                    "Steps will be automatically reordered fastest-first."
                ),
            },
        },
        "required": ["steps"],
    },
}

UPDATE_PLAN_STEP_TOOL: dict[str, Any] = {
    "name": "update_plan_step",
    "description": (
        "Mark a plan step as done, in_progress, or skipped, with an optional "
        "result summary. Call this after completing each step so progress is "
        "tracked and persisted."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "step_number": {
                "type": "integer",
                "description": "The 1-based step number to update.",
            },
            "status": {
                "type": "string",
                "enum": ["pending", "in_progress", "done", "skipped"],
                "description": "New status for the step.",
            },
            "result_summary": {
                "type": "string",
                "description": (
                    "Brief summary of what happened (e.g., '3 SQLi findings', "
                    "'no vulnerabilities found', 'blocked by WAF')."
                ),
            },
        },
        "required": ["step_number", "status"],
    },
}
