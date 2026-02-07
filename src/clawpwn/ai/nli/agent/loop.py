"""Core agentic loop: send messages, handle tool_use, collect answers."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from clawpwn.ai.llm import LLMClient
from clawpwn.ai.nli.tool_executors import dispatch_tool, format_availability_report
from clawpwn.ai.nli.tools import FAST_PATH_TOOLS, get_all_tools

from .prompt import MAX_TOOL_ROUNDS, ROUTING_MAX_TOKENS, SYSTEM_PROMPT_TEMPLATE, TOOL_ACTION_MAP

# Type alias for the live progress callback.
ProgressCallback = Callable[[str], None]


def _format_tool_call(name: str, params: dict[str, Any]) -> str:
    """Format a tool invocation as a readable one-liner."""
    parts = [f"{k}={v!r}" for k, v in params.items() if v is not None]
    return f"→ {name}({', '.join(parts)})"


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
        context = self._get_project_context()
        if context:
            return f"{self._base_system_prompt}\n\nCurrent project state:\n{context}"
        return self._base_system_prompt

    def _get_project_context(self) -> str:
        """Fetch active target and phase from session, if available."""
        try:
            from clawpwn.config import get_project_db_path
            from clawpwn.modules.session import SessionManager

            db_path = get_project_db_path(self.project_dir)
            if not db_path:
                return ""
            session = SessionManager(db_path)
            state = session.get_state()
            if not state:
                return ""
            parts: list[str] = []
            if state.target:
                parts.append(f"Active target: {state.target}")
            if state.current_phase:
                parts.append(f"Phase: {state.current_phase}")
            if state.findings_count:
                parts.append(
                    f"Findings so far: {state.findings_count} "
                    f"({state.critical_count} critical, {state.high_count} high)"
                )
            return "\n".join(parts)
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, user_message: str, debug: bool = False) -> dict[str, Any]:
        """Process a single user message through the tool-use loop.

        Returns a result dict compatible with the existing NLI response format.
        """
        # Set thread-local debug state
        if debug:
            from clawpwn.utils.debug import debug_agent_round, set_debug_enabled

            set_debug_enabled(True)

        messages: list[dict[str, Any]] = [{"role": "user", "content": user_message}]
        progress_updates: list[str] = []
        action = "unknown"
        suggestions: list[dict[str, str]] = []
        is_streamed = self.on_progress is not None
        last_text_parts: list[str] = []  # only the most recent round's text
        model_used: str | None = None

        for _round in range(MAX_TOOL_ROUNDS):
            # Log the agent round if debug is enabled
            if debug:
                context_info = None
                context_str = self._get_project_context()
                if context_str:
                    # Simplify for display
                    lines = context_str.split("\n")
                    context_info = ", ".join(lines)
                debug_agent_round(round_num=_round + 1, context_info=context_info)

            response = self.llm.chat_with_tools(
                messages=messages,
                tools=self._tools,
                system_prompt=self._system_prompt,
                max_tokens=ROUTING_MAX_TOKENS,
                debug=debug,
            )
            model_used = getattr(response, "model", None)

            # Collect text blocks Claude emitted in this round
            text_parts, tool_calls = self._split_content(response.content)
            last_text_parts = text_parts
            for tp in text_parts:
                self._emit(tp)

            if response.stop_reason != "tool_use" or not tool_calls:
                # Final text answer — use only this round's text
                final = "\n".join(last_text_parts) if last_text_parts else "Done."
                return self._build_result(
                    success=True,
                    text=final,
                    action=action,
                    progress=progress_updates,
                    suggestions=suggestions,
                    streamed=is_streamed,
                    model=model_used,
                )

            # Execute each tool call
            tool_results: list[dict[str, Any]] = []
            for tc in tool_calls:
                tool_name = tc.name
                tool_input = tc.input
                action = TOOL_ACTION_MAP.get(tool_name, "unknown")

                call_str = _format_tool_call(tool_name, tool_input)
                progress_updates.append(call_str)
                self._emit(call_str)

                result_text = dispatch_tool(tool_name, tool_input, self.project_dir)
                done_str = f"✓ [{tool_name}] done"
                progress_updates.append(done_str)
                self._emit(done_str)

                if tool_name == "suggest_tools":
                    suggestions.extend(tool_input.get("suggestions", []))

                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tc.id,
                        "content": result_text,
                    }
                )

                # Fast-path: skip analysis round-trip for simple tools
                if tool_name in FAST_PATH_TOOLS and len(tool_calls) == 1:
                    if debug:
                        debug_agent_round(
                            round_num=_round + 1,
                            decision=f"fast-path: single {tool_name} call, skipping analysis",
                        )
                    return self._build_result(
                        success=True,
                        text=result_text,
                        action=action,
                        progress=progress_updates,
                        suggestions=suggestions,
                        streamed=is_streamed,
                        model=model_used,
                    )

            # Append assistant + tool results and loop for analysis
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

        # Exhausted rounds — use last text Claude produced
        final = "\n".join(last_text_parts) if last_text_parts else "Scan complete."
        return self._build_result(
            success=True,
            text=final,
            action=action,
            progress=progress_updates,
            suggestions=suggestions,
            streamed=is_streamed,
            model=model_used,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _emit(self, message: str) -> None:
        """Send a progress message to the live callback, if registered."""
        if self.on_progress is not None:
            self.on_progress(message)

    @staticmethod
    def _split_content(content: Any) -> tuple[list[str], list[Any]]:
        """Separate text blocks from tool_use blocks."""
        texts: list[str] = []
        tools: list[Any] = []
        if not isinstance(content, list):
            return texts, tools
        for block in content:
            if getattr(block, "type", None) == "text":
                text = getattr(block, "text", "").strip()
                if text:
                    texts.append(text)
            elif getattr(block, "type", None) == "tool_use":
                tools.append(block)
        return texts, tools

    @staticmethod
    def _build_result(
        *,
        success: bool,
        text: str,
        action: str,
        progress: list[str],
        suggestions: list[dict[str, str]],
        streamed: bool = False,
        model: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "success": success,
            "response": text,
            "action": action,
            "progress_updates": progress,
            "progress_streamed": streamed,
        }
        if suggestions:
            result["suggestions"] = suggestions
        if model:
            result["model"] = model
        return result
