"""Anthropic tool use support and integration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .client import LLMClient


def chat_with_tools(
    client: LLMClient,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    system_prompt: str | None = None,
    *,
    model: str | None = None,
    max_tokens: int = 1024,
    debug: bool = False,
    thinking_budget: int | None = None,
) -> Any:
    """Send a message with tool definitions via the Anthropic SDK.

    Returns the raw ``anthropic.types.Message`` object so callers can
    inspect ``stop_reason``, ``content`` blocks (text / tool_use), etc.
    """
    if client.provider != "anthropic":
        raise RuntimeError("chat_with_tools requires the Anthropic provider")

    # Set thread-local debug state
    if debug:
        from clawpwn.utils.debug import debug_llm_request, debug_llm_response, set_debug_enabled

        set_debug_enabled(True)

        # Log the request
        debug_llm_request(
            model=model or client.routing_model,
            max_tokens=max_tokens,
            system_prompt=system_prompt,
            tools=tools,
            messages=messages,
        )

    kwargs: dict[str, Any] = {
        "model": model or client.routing_model,
        "max_tokens": max_tokens,
        "messages": messages,
        "tools": tools,
    }
    if system_prompt:
        kwargs["system"] = [
            {
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }
        ]

    # Anthropic constraints:
    # - max_tokens must be greater than thinking.budget_tokens
    # - thinking.budget_tokens must be at least 1024 when enabled
    # Clamp/disable defensively so misconfigured constants don't hard-fail requests.
    if thinking_budget and max_tokens > 1:
        safe_budget = min(thinking_budget, max_tokens - 1)
        if safe_budget >= 1024:
            kwargs["thinking"] = {
                "type": "enabled",
                "budget_tokens": safe_budget,
            }

    response = client.anthropic_sdk.messages.create(**kwargs)

    # Log the response
    if debug:
        content_types = [block.type for block in response.content]
        token_usage = {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
        }
        debug_llm_response(
            stop_reason=response.stop_reason,
            content_types=content_types,
            token_usage=token_usage,
        )

    return response
