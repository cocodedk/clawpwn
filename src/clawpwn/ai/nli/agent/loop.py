"""Core agentic loop: send messages, handle tool_use, collect answers."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from clawpwn.ai.llm import LLMClient
from clawpwn.ai.nli.tool_executors import dispatch_tool, format_availability_report
from clawpwn.ai.nli.tools import FAST_PATH_TOOLS, get_all_tools

from .context import get_project_context
from .executor import run_agent_loop
from .prompt import SYSTEM_PROMPT_TEMPLATE

# Type alias for the live progress callback.
ProgressCallback = Callable[[str], None]

# Re-export for backward compatibility
__all__ = ["ToolUseAgent", "ProgressCallback", "dispatch_tool", "FAST_PATH_TOOLS"]


class ToolUseAgent:
    """Drive a multi-turn tool-use conversation with Claude."""

    def __init__(self, llm: LLMClient, project_dir: Path):
        self.llm = llm
        self.project_dir = project_dir
        self._tools = get_all_tools()
        self._base_system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
            tool_status=format_availability_report()
        )
        self.on_progress: ProgressCallback | None = None

    @property
    def _system_prompt(self) -> str:
        """Build system prompt with current project context (target, phase)."""
        context = get_project_context(self.project_dir)
        if context:
            return f"{self._base_system_prompt}\n\nCurrent project state:\n{context}"
        return self._base_system_prompt

    def run(self, user_message: str, debug: bool = False) -> dict[str, Any]:
        """Process a single user message through the tool-use loop.

        Returns a result dict compatible with the existing NLI response format.
        """
        return run_agent_loop(
            llm=self.llm,
            project_dir=self.project_dir,
            tools=self._tools,
            system_prompt=self._system_prompt,
            user_message=user_message,
            on_progress=self.on_progress,
            debug=debug,
        )
