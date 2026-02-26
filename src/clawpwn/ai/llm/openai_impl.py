"""OpenAI/OpenRouter provider implementation for LLM client."""

import json


def chat_openai(
    client, message: str, system_prompt: str | None = None, *, model: str | None = None
) -> str:
    """Chat with OpenAI API."""
    if getattr(client, "client", None) is None:
        raise RuntimeError("LLM client is closed; cannot call _chat_openai.")
    if client.provider == "openrouter":
        base = client.base_url or "https://openrouter.ai/api/v1"
    else:
        base = client.base_url or "https://api.openai.com/v1"

    url = f"{base.rstrip('/')}/chat/completions"

    headers = {
        "Authorization": f"Bearer {client.api_key}",
        "Content-Type": "application/json",
    }

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": message})

    payload = {
        "model": model or client.model,
        "messages": messages,
        "max_tokens": 4096,
    }

    response = client.client.post(url, headers=headers, json=payload)
    raw_text = response.text

    if response.status_code >= 400:
        response.raise_for_status()

    try:
        data = response.json()
    except json.JSONDecodeError as e:
        raise ValueError(
            f"OpenAI/OpenRouter API returned invalid JSON (status {response.status_code}): {e}. "
            f"Raw response: {raw_text[:500]!r}"
        ) from e

    if not isinstance(data, dict):
        raise ValueError(
            f"OpenAI/OpenRouter API response is not a dict (got {type(data).__name__}). "
            f"Raw response: {raw_text[:500]!r}"
        )
    choices = data.get("choices")
    if choices is None or not isinstance(choices, list):
        raise ValueError(
            f"OpenAI/OpenRouter API response missing or invalid 'choices' (got {type(choices).__name__}). "
            f"Raw response: {raw_text[:500]!r}"
        )
    if len(choices) == 0:
        raise ValueError(
            f"OpenAI/OpenRouter API response 'choices' is an empty list. "
            f"Raw response: {raw_text[:500]!r}"
        )
    first = choices[0]
    if not isinstance(first, dict):
        raise ValueError(
            f"OpenAI/OpenRouter API response choices[0] is not a dict. "
            f"Raw response: {raw_text[:500]!r}"
        )
    message = first.get("message")
    if not isinstance(message, dict) or "content" not in message:
        raise ValueError(
            f"OpenAI/OpenRouter API response choices[0] missing 'message' with 'content'. "
            f"Raw response: {raw_text[:500]!r}"
        )
    return message["content"]
