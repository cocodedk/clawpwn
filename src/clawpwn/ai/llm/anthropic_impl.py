"""Anthropic provider implementation for LLM client."""

import json
from typing import Any


def chat_anthropic(client, message: str, system_prompt: str | None = None) -> str:
    """Chat with Claude API."""
    if getattr(client, "client", None) is None:
        raise RuntimeError("LLM client is closed; cannot call _chat_anthropic.")
    base = client.base_url or "https://api.anthropic.com"
    url = f"{base.rstrip('/')}/v1/messages"

    headers = {
        "x-api-key": client.api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }

    payload: dict[str, Any] = {
        "model": client.model,
        "max_tokens": 4096,
        "messages": [{"role": "user", "content": message}],
    }

    if system_prompt:
        payload["system"] = system_prompt

    response = client.client.post(url, headers=headers, json=payload)
    raw_text = response.text

    if response.status_code >= 400:
        response.raise_for_status()

    try:
        data = response.json()
    except json.JSONDecodeError as e:
        raise ValueError(
            f"Anthropic API returned invalid JSON (status {response.status_code}): {e}. "
            f"Raw response: {raw_text[:500]!r}"
        ) from e

    if not isinstance(data, dict):
        raise ValueError(
            f"Anthropic API response is not a dict (got {type(data).__name__}). "
            f"Raw response: {raw_text[:500]!r}"
        )
    content = data.get("content")
    if not isinstance(content, list):
        raise ValueError(
            f"Anthropic API response missing or invalid 'content' (got {type(content).__name__}). "
            f"Raw response: {raw_text[:500]!r}"
        )
    if len(content) == 0:
        raise ValueError(
            f"Anthropic API response 'content' is empty. Raw response: {raw_text[:500]!r}"
        )
    first = content[0]
    if not isinstance(first, dict) or "text" not in first:
        raise ValueError(
            f"Anthropic API response content[0] missing 'text' key. "
            f"Raw response: {raw_text[:500]!r}"
        )
    return first["text"]
