"""Claude tool-use agent for ClawPwn NLI."""

from .loop import ToolUseAgent
from .prompt import (
    ANALYSIS_MAX_TOKENS,
    MAX_TOOL_ROUNDS,
    ROUTING_MAX_TOKENS,
    SYSTEM_PROMPT_TEMPLATE,
    TOOL_ACTION_MAP,
)

__all__ = [
    "ANALYSIS_MAX_TOKENS",
    "MAX_TOOL_ROUNDS",
    "ROUTING_MAX_TOKENS",
    "SYSTEM_PROMPT_TEMPLATE",
    "TOOL_ACTION_MAP",
    "ToolUseAgent",
]
