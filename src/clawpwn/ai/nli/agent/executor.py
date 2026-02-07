"""Main agent execution loop."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from clawpwn.ai.llm import LLMClient
from clawpwn.ai.nli.tool_executors import dispatch_tool
from clawpwn.ai.nli.tools import FAST_PATH_TOOLS

from .prompt import MAX_TOOL_ROUNDS, ROUTING_MAX_TOKENS, THINKING_BUDGET, TOOL_ACTION_MAP
from .result_builder import build_result, format_tool_call, split_content


def run_agent_loop(
    llm: LLMClient,
    project_dir: Path,
    tools: list[dict[str, Any]],
    system_prompt: str,
    user_message: str,
    on_progress: callable | None = None,
    debug: bool = False,
) -> dict[str, Any]:
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
    is_streamed = on_progress is not None
    last_text_parts: list[str] = []  # only the most recent round's text
    model_used: str | None = None

    def _emit(message: str) -> None:
        """Send a progress message to the live callback, if registered."""
        if on_progress is not None:
            on_progress(message)

    for _round in range(MAX_TOOL_ROUNDS):
        # Log the agent round if debug is enabled
        if debug:
            from .context import get_project_context

            context_info = None
            context_str = get_project_context(project_dir)
            if context_str:
                # Simplify for display
                lines = context_str.split("\n")
                context_info = ", ".join(lines)
            debug_agent_round(round_num=_round + 1, context_info=context_info)

        response = llm.chat_with_tools(
            messages=messages,
            tools=tools,
            system_prompt=system_prompt,
            max_tokens=ROUTING_MAX_TOKENS,
            debug=debug,
            thinking_budget=THINKING_BUDGET,
        )
        model_used = getattr(response, "model", None)

        # In debug mode, emit thinking blocks for visibility
        if debug:
            for block in response.content:
                if getattr(block, "type", None) == "thinking":
                    thinking_text = getattr(block, "thinking", "")
                    if thinking_text:
                        # Truncate for brevity in output
                        preview = (
                            thinking_text[:500] + "..."
                            if len(thinking_text) > 500
                            else thinking_text
                        )
                        _emit(f"[THINKING] {preview}")

        # Collect text blocks Claude emitted in this round
        text_parts, tool_calls = split_content(response.content)
        last_text_parts = text_parts
        for tp in text_parts:
            _emit(tp)

        if response.stop_reason != "tool_use" or not tool_calls:
            # Final text answer — use only this round's text
            final = "\n".join(last_text_parts) if last_text_parts else "Done."
            return build_result(
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

            call_str = format_tool_call(tool_name, tool_input)
            progress_updates.append(call_str)
            _emit(call_str)

            result_text = dispatch_tool(tool_name, tool_input, project_dir)
            done_str = f"✓ [{tool_name}] done"
            progress_updates.append(done_str)
            _emit(done_str)

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
                return build_result(
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
    return build_result(
        success=True,
        text=final,
        action=action,
        progress=progress_updates,
        suggestions=suggestions,
        streamed=is_streamed,
        model=model_used,
    )
