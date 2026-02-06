"""Execute tool calls requested by the Claude agent.

Each public ``execute_*`` function takes the tool-call ``input`` dict and a
``project_dir`` and returns a plain-text result string that gets sent back to
Claude as a ``tool_result``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .availability import (
    EXTERNAL_TOOLS,
    check_tool_availability,
    enrich_missing_tool_error,
    execute_check_available_tools,
    execute_suggest_tools,
    format_availability_report,
)
from .scan_executors import (
    execute_discover_hosts,
    execute_network_scan,
    execute_web_scan,
)
from .support_executors import (
    execute_check_status,
    execute_research_vulnerabilities,
    execute_set_target,
    execute_show_help,
)

__all__ = [
    "EXTERNAL_TOOLS",
    "check_tool_availability",
    "dispatch_tool",
    "enrich_missing_tool_error",
    "execute_check_available_tools",
    "execute_check_status",
    "execute_discover_hosts",
    "execute_network_scan",
    "execute_research_vulnerabilities",
    "execute_set_target",
    "execute_show_help",
    "execute_suggest_tools",
    "execute_web_scan",
    "format_availability_report",
]

# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

TOOL_EXECUTORS: dict[str, Any] = {
    "web_scan": execute_web_scan,
    "network_scan": execute_network_scan,
    "discover_hosts": execute_discover_hosts,
    "check_status": execute_check_status,
    "set_target": execute_set_target,
    "research_vulnerabilities": execute_research_vulnerabilities,
    "show_help": execute_show_help,
    "check_available_tools": execute_check_available_tools,
    "suggest_tools": execute_suggest_tools,
}


def dispatch_tool(name: str, params: dict[str, Any], project_dir: Path) -> str:
    """Run the named tool and return a result string.

    Unknown tool names and execution errors are returned as error text
    (not raised) so Claude can react gracefully.
    """
    executor = TOOL_EXECUTORS.get(name)
    if executor is None:
        return f"Unknown tool: {name}"
    try:
        return executor(params, project_dir)
    except Exception as exc:
        return enrich_missing_tool_error(f"Tool '{name}' failed: {exc}")
