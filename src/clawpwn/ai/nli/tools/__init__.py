"""Anthropic tool-use schema definitions for ClawPwn capabilities."""

from typing import Any

from .attack_tools import CREDENTIAL_TEST_TOOL, RUN_CUSTOM_SCRIPT_TOOL
from .recon_tools import FINGERPRINT_TARGET_TOOL, WEB_SEARCH_TOOL
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
    "CREDENTIAL_TEST_TOOL",
    "DISCOVER_HOSTS_TOOL",
    "FAST_PATH_TOOLS",
    "FINGERPRINT_TARGET_TOOL",
    "NETWORK_SCAN_TOOL",
    "RESEARCH_VULNERABILITIES_TOOL",
    "RUN_CUSTOM_SCRIPT_TOOL",
    "SET_TARGET_TOOL",
    "SHOW_HELP_TOOL",
    "SUGGEST_TOOLS_TOOL",
    "WEB_SCAN_TOOL",
    "WEB_SEARCH_TOOL",
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
        WEB_SEARCH_TOOL,
        FINGERPRINT_TARGET_TOOL,
        CREDENTIAL_TEST_TOOL,
        RUN_CUSTOM_SCRIPT_TOOL,
    ]


# Tools whose results can be returned directly without a second Claude round-trip.
FAST_PATH_TOOLS = frozenset({"check_status", "set_target", "show_help", "check_available_tools"})
