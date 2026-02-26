"""Core agentic loop: send messages, handle tool_use, collect answers."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from clawpwn.ai.llm import LLMClient
from clawpwn.ai.nli.tool_executors import dispatch_tool, format_availability_report
from clawpwn.ai.nli.tools import FAST_PATH_TOOLS, get_all_tools
from clawpwn.ai.nli.tools.tool_metadata import format_speed_table

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
            tool_status=format_availability_report(),
            speed_table=format_speed_table(),
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

        Routes between the code-driven plan executor (for scan/attack
        requests) and the conversational agent loop (for questions/status).
        """
        from .plan_helpers import classify_intent

        has_pending = self._has_pending_plan()
        intent = classify_intent(self.llm, user_message, has_pending)

        if intent in ("plan_execute", "plan_new"):
            from .plan_executor import run_plan_executor

            return run_plan_executor(
                llm=self.llm,
                project_dir=self.project_dir,
                tools=self._tools,
                system_prompt=self._system_prompt,
                user_message=user_message,
                on_progress=self.on_progress,
                debug=debug,
                replace_plan=intent == "plan_new",
            )

        return run_agent_loop(
            llm=self.llm,
            project_dir=self.project_dir,
            tools=self._tools,
            system_prompt=self._system_prompt,
            user_message=user_message,
            on_progress=self.on_progress,
            debug=debug,
        )

    def _has_pending_plan(self) -> bool:
        """Check if a pending plan exists for resume."""
        try:
            from clawpwn.config import get_project_db_path
            from clawpwn.modules.session import SessionManager

            db_path = get_project_db_path(self.project_dir)
            if not db_path:
                return False
            session = SessionManager(db_path)
            return session.get_next_pending_step() is not None
        except Exception:
            return False
