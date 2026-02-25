"""Result builders and content splitters for agent responses."""

from __future__ import annotations

from typing import Any


def split_content(content: Any) -> tuple[list[str], list[Any]]:
    """Separate text blocks from tool_use blocks (ignore thinking blocks)."""
    texts: list[str] = []
    tools: list[Any] = []
    if not isinstance(content, list):
        return texts, tools
    for block in content:
        block_type = getattr(block, "type", None)
        if block_type == "text":
            text = getattr(block, "text", "").strip()
            if text:
                texts.append(text)
        elif block_type == "tool_use":
            tools.append(block)
        # Ignore "thinking" blocks — they're for Claude's internal reasoning
    return texts, tools


def build_result(
    *,
    success: bool,
    text: str,
    action: str,
    progress: list[str],
    suggestions: list[dict[str, str]],
    streamed: bool = False,
    model: str | None = None,
) -> dict[str, Any]:
    """Build a result dict compatible with NLI response format."""
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


def format_tool_call(name: str, params: dict[str, Any]) -> str:
    """Format a tool invocation as a readable one-liner."""
    parts = [f"{k}={v!r}" for k, v in params.items() if v is not None]
    return f"→ {name}({', '.join(parts)})"
