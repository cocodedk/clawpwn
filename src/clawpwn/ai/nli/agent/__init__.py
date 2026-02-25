"""Agent module for tool-use conversations."""

from collections.abc import Callable

from .loop import ToolUseAgent
from .plan_executor import run_plan_executor
from .plan_helpers import classify_intent
from .prompt import (
    ANALYSIS_MAX_TOKENS,
    MAX_TOOL_ROUNDS,
    ROUTING_MAX_TOKENS,
    SYSTEM_PROMPT_TEMPLATE,
    TOOL_ACTION_MAP,
)
from .result_builder import build_result, format_tool_call, split_content

# Type alias
ProgressCallback = Callable[[str], None]

__all__ = [
    "ANALYSIS_MAX_TOKENS",
    "MAX_TOOL_ROUNDS",
    "ProgressCallback",
    "ROUTING_MAX_TOKENS",
    "SYSTEM_PROMPT_TEMPLATE",
    "TOOL_ACTION_MAP",
    "ToolUseAgent",
    "build_result",
    "classify_intent",
    "format_tool_call",
    "run_plan_executor",
    "split_content",
]
