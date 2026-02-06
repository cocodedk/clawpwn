"""Core agentic loop: send messages, handle tool_use, collect answers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from clawpwn.ai.llm import LLMClient
from clawpwn.ai.nli.tool_executors import dispatch_tool, format_availability_report
from clawpwn.ai.nli.tools import FAST_PATH_TOOLS, get_all_tools

from .prompt import MAX_TOOL_ROUNDS, ROUTING_MAX_TOKENS, SYSTEM_PROMPT_TEMPLATE, TOOL_ACTION_MAP


class ToolUseAgent:
    """Drive a multi-turn tool-use conversation with Claude."""

    def __init__(self, llm: LLMClient, project_dir: Path):
        self.llm = llm
        self.project_dir = project_dir
        self._tools = get_all_tools()
        self._system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
            tool_status=format_availability_report()
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, user_message: str) -> dict[str, Any]:
        """Process a single user message through the tool-use loop.

        Returns a result dict compatible with the existing NLI response format.
        """
        messages: list[dict[str, Any]] = [{"role": "user", "content": user_message}]
        reasoning_parts: list[str] = []
        progress_updates: list[str] = []
        action = "unknown"
        suggestions: list[dict[str, str]] = []

        for _round in range(MAX_TOOL_ROUNDS):
            response = self.llm.chat_with_tools(
                messages=messages,
                tools=self._tools,
                system_prompt=self._system_prompt,
                max_tokens=ROUTING_MAX_TOKENS,
            )

            # Collect text blocks Claude emitted before/alongside tools
            text_parts, tool_calls = self._split_content(response.content)
            if text_parts:
                reasoning_parts.extend(text_parts)

            if response.stop_reason != "tool_use" or not tool_calls:
                return self._build_result(
                    success=True,
                    text="\n".join(reasoning_parts) if reasoning_parts else "Done.",
                    action=action,
                    reasoning=None,
                    progress=progress_updates,
                    suggestions=suggestions,
                )

            # Execute each tool call
            tool_results: list[dict[str, Any]] = []
            for tc in tool_calls:
                tool_name = tc.name
                tool_input = tc.input
                action = TOOL_ACTION_MAP.get(tool_name, "unknown")
                progress_updates.append(f"● [{tool_name}] executing…")

                result_text = dispatch_tool(tool_name, tool_input, self.project_dir)
                progress_updates.append(f"✓ [{tool_name}] done")

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
                    reasoning = "\n".join(reasoning_parts) if reasoning_parts else None
                    return self._build_result(
                        success=True,
                        text=result_text,
                        action=action,
                        reasoning=reasoning,
                        progress=progress_updates,
                        suggestions=suggestions,
                    )

            # Append assistant + tool results and loop for analysis
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

        # Exhausted rounds
        return self._build_result(
            success=True,
            text="\n".join(reasoning_parts) if reasoning_parts else "Scan complete.",
            action=action,
            reasoning=None,
            progress=progress_updates,
            suggestions=suggestions,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

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
        reasoning: str | None,
        progress: list[str],
        suggestions: list[dict[str, str]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "success": success,
            "response": text,
            "action": action,
            "progress_updates": progress,
            "progress_streamed": False,
        }
        if reasoning:
            result["reasoning"] = reasoning
        if suggestions:
            result["suggestions"] = suggestions
        return result
