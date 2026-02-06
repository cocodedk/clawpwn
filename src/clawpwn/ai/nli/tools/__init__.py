"""Anthropic tool-use schema definitions for ClawPwn capabilities."""

from typing import Any

from .scan_tools import DISCOVER_HOSTS_TOOL, NETWORK_SCAN_TOOL, WEB_SCAN_TOOL
from .support_tools import (
    CHECK_AVAILABLE_TOOLS_TOOL,
    CHECK_STATUS_TOOL,
    RESEARCH_VULNERABILITIES_TOOL,
    SET_TARGET_TOOL,
    SHOW_HELP_TOOL,
    SUGGEST_TOOLS_TOOL,
)

__all__ = [
    "CHECK_AVAILABLE_TOOLS_TOOL",
    "CHECK_STATUS_TOOL",
    "DISCOVER_HOSTS_TOOL",
    "FAST_PATH_TOOLS",
    "NETWORK_SCAN_TOOL",
    "RESEARCH_VULNERABILITIES_TOOL",
    "SET_TARGET_TOOL",
    "SHOW_HELP_TOOL",
    "SUGGEST_TOOLS_TOOL",
    "WEB_SCAN_TOOL",
    "get_all_tools",
]


def get_all_tools() -> list[dict[str, Any]]:
    """Return all tool definitions for the Anthropic Messages API."""
    return [
        WEB_SCAN_TOOL,
        NETWORK_SCAN_TOOL,
        DISCOVER_HOSTS_TOOL,
        CHECK_STATUS_TOOL,
        SET_TARGET_TOOL,
        RESEARCH_VULNERABILITIES_TOOL,
        SHOW_HELP_TOOL,
        CHECK_AVAILABLE_TOOLS_TOOL,
        SUGGEST_TOOLS_TOOL,
    ]


# Tools whose results can be returned directly without a second Claude round-trip.
FAST_PATH_TOOLS = frozenset({"check_status", "set_target", "show_help", "check_available_tools"})
