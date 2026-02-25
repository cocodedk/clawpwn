"""Debug utilities for NLI agent visibility.

Thread-safe debug logging with rich formatting for console sessions.
"""

import json
import threading
from typing import Any

from rich.console import Console
from rich.syntax import Syntax

# Thread-local storage for debug state
_debug_state = threading.local()


def set_debug_enabled(enabled: bool) -> None:
    """Set debug mode for the current thread/session."""
    _debug_state.enabled = enabled


def is_debug_enabled() -> bool:
    """Check if debug mode is enabled for the current thread/session."""
    return getattr(_debug_state, "enabled", False)


def debug_print(category: str, message: str, **data: Any) -> None:
    """Print debug information if debug mode is enabled.

    Args:
        category: Debug category (llm, agent, tool, config)
        message: Main message to display
        **data: Additional key-value pairs to display
    """
    if not is_debug_enabled():
        return
    console = Console()
    console.print(f"[DEBUG:{category}] {message}", style="bold cyan")
    for key, value in data.items():
        if value is None:
            continue
        # Special formatting for different types
        if isinstance(value, dict):
            try:
                json_str = json.dumps(value, indent=2)
                syntax = Syntax(json_str, "json", theme="monokai", line_numbers=False)
                console.print(f"  {key}:", style="dim")
                console.print(syntax)
            except (TypeError, ValueError):
                console.print(f"  {key}: {value}", style="dim")
        elif isinstance(value, list):
            console.print(f"  {key}: {', '.join(str(v) for v in value)}", style="dim")
        elif isinstance(value, str) and len(value) > 100:
            # Truncate long strings
            console.print(f"  {key}: {value[:100]}... ({len(value)} chars)", style="dim")
        else:
            console.print(f"  {key}: {value}", style="dim")


def debug_llm_request(
    model: str,
    max_tokens: int,
    system_prompt: str | None,
    tools: list[dict[str, Any]],
    messages: list[dict[str, Any]],
) -> None:
    """Log an LLM request in debug mode.

    Args:
        model: Model name
        max_tokens: Max tokens for response
        system_prompt: System prompt (will be truncated if long)
        tools: List of tool schemas
        messages: List of message dicts
    """
    if not is_debug_enabled():
        return
    tool_names = [t.get("name", "unknown") for t in tools]
    tool_summary = f"{', '.join(tool_names[:3])}"
    if len(tools) > 3:
        tool_summary += f", +{len(tools) - 3} more"
    system_display = None
    if system_prompt:
        if len(system_prompt) > 500:
            system_display = f"{len(system_prompt)} chars"
        else:
            system_display = f"{len(system_prompt)} chars"
    user_msg = ""
    for msg in messages:
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                user_msg = content[:80] if len(content) > 80 else content
            break
    debug_print(
        "llm",
        f"→ {model} (max_tokens={max_tokens})",
        System=system_display,
        User=user_msg if user_msg else None,
        Tools=tool_summary,
    )


def debug_llm_response(
    stop_reason: str,
    content_types: list[str],
    token_usage: dict[str, int] | None,
) -> None:
    """Log an LLM response in debug mode.

    Args:
        stop_reason: Why the model stopped (e.g., 'tool_use', 'end_turn')
        content_types: Types of content blocks (e.g., ['text'], ['tool_use'])
        token_usage: Token counts (input_tokens, output_tokens, total)
    """
    if not is_debug_enabled():
        return
    usage_str = None
    if token_usage:
        inp = token_usage.get("input_tokens", 0)
        out = token_usage.get("output_tokens", 0)
        total = token_usage.get("total_tokens") or (inp + out)
        usage_str = f"{inp}↓/{out}↑/{total} total"
    debug_print(
        "llm",
        f"← stop_reason={stop_reason}",
        Content=", ".join(content_types),
        Tokens=usage_str,
    )


def debug_agent_round(
    round_num: int,
    context_info: str | None = None,
    decision: str | None = None,
) -> None:
    """Log an agent loop round in debug mode.

    Args:
        round_num: Current round number
        context_info: Project context being used (e.g., "target=http://...")
        decision: What the agent decided (e.g., "fast-path: single tool")
    """
    if not is_debug_enabled():
        return
    debug_print(
        "agent",
        f"Round {round_num}",
        Context=context_info,
        Decision=decision,
    )


def debug_tool_execution(
    tool_name: str,
    params: dict[str, Any],
    start: bool = True,
    elapsed: float | None = None,
    result_size: int | None = None,
) -> None:
    """Log tool execution in debug mode.

    Args:
        tool_name: Name of the tool being executed
        params: Tool parameters
        start: True for start event, False for completion
        elapsed: Time elapsed in seconds (for completion event)
        result_size: Size of result string in chars (for completion event)
    """
    if not is_debug_enabled():
        return
    if start:
        simple_params = {}
        for key, value in params.items():
            if isinstance(value, str) and len(value) > 50:
                simple_params[key] = f"{value[:50]}..."
            else:
                simple_params[key] = value
        debug_print(
            "tool",
            f"dispatch_tool({tool_name}) +0.0s",
            Params=simple_params,
        )
    else:
        debug_print(
            "tool",
            f"dispatch_tool({tool_name}) completed +{elapsed:.1f}s"
            if elapsed
            else f"dispatch_tool({tool_name}) completed",
            Result=f"{result_size} chars" if result_size else None,
        )
