"""LLM client for ClawPwn AI integration."""

import json
from pathlib import Path
from typing import Any

import httpx

from clawpwn.config import (
    get_api_key,
    get_llm_base_url,
    get_llm_model,
    get_llm_provider,
    get_project_env_path,
)


class LLMClient:
    """Client for interacting with LLM APIs (Claude, GPT-4, etc.)."""

    def __init__(
        self,
        provider: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        project_dir: Path | None = None,
    ):
        self.provider = (provider or get_llm_provider(project_dir)).lower()
        self.project_dir = project_dir

        # Get API key from multiple sources
        if api_key:
            self.api_key = api_key
        else:
            self.api_key = self._get_api_key_with_fallback()

        # Default models
        self.model = (
            model
            or get_llm_model(project_dir)
            or {
                "anthropic": "claude-3-5-sonnet-20241022",
                "openai": "gpt-4o",
                "openrouter": "openai/gpt-4o-mini",
            }.get(self.provider, "claude-3-5-sonnet-20241022")
        )

        self.base_url = get_llm_base_url(project_dir)

        self.client = httpx.Client(timeout=60.0)

    def close(self) -> None:
        """Close the underlying HTTP client and release the connection pool."""
        client = getattr(self, "client", None)
        if client is not None:
            client.close()
            self.client = None  # idempotent; avoid double-close and __del__ no-op

    def __enter__(self) -> "LLMClient":
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _get_api_key_with_fallback(self) -> str:
        """Get API key from multiple sources with helpful error messages."""
        api_key = get_api_key(self.provider, self.project_dir)

        if not api_key:
            # Create helpful error message with setup instructions
            env_var = {
                "anthropic": "ANTHROPIC_API_KEY",
                "openai": "OPENAI_API_KEY",
                "openrouter": "OPENROUTER_API_KEY",
            }.get(self.provider, f"{self.provider.upper()}_API_KEY")

            env_path = (
                get_project_env_path(self.project_dir)
                if self.project_dir
                else Path(".clawpwn/.env")
            )

            error_msg = f"""API key not found for provider: {self.provider}

To set your API key, choose one of these methods:

1. Environment variable (quick):
   export CLAWPWN_LLM_API_KEY=your-api-key
   export CLAWPWN_LLM_PROVIDER={self.provider}
   # or legacy: export {env_var}=your-api-key

2. Project .env file (recommended per project):
   echo "CLAWPWN_LLM_PROVIDER={self.provider}" >> {env_path}
   echo "CLAWPWN_LLM_API_KEY=your-api-key" >> {env_path}

3. Global config file:
   echo "CLAWPWN_LLM_API_KEY: your-api-key" >> ~/.clawpwn/config.yml

Get your API key from:
- Anthropic: https://console.anthropic.com/
- OpenAI: https://platform.openai.com/
- OpenRouter: https://openrouter.ai/
"""
            raise ValueError(error_msg)

        return api_key

    def chat(self, message: str, system_prompt: str | None = None) -> str:
        """Send a chat message and get a response."""
        if self.provider == "anthropic":
            return self._chat_anthropic(message, system_prompt)
        elif self.provider in ("openai", "openrouter"):
            return self._chat_openai(message, system_prompt)
        else:
            raise ValueError(f"Unknown provider: {self.provider}")

    def _chat_anthropic(self, message: str, system_prompt: str | None = None) -> str:
        """Chat with Claude API."""
        if getattr(self, "client", None) is None:
            raise RuntimeError("LLM client is closed; cannot call _chat_anthropic.")
        base = self.base_url or "https://api.anthropic.com"
        url = f"{base.rstrip('/')}/v1/messages"

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": message}],
        }

        if system_prompt:
            payload["system"] = system_prompt

        response = self.client.post(url, headers=headers, json=payload)
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

    def _chat_openai(self, message: str, system_prompt: str | None = None) -> str:
        """Chat with OpenAI API."""
        if getattr(self, "client", None) is None:
            raise RuntimeError("LLM client is closed; cannot call _chat_openai.")
        if self.provider == "openrouter":
            base = self.base_url or "https://openrouter.ai/api/v1"
        else:
            base = self.base_url or "https://api.openai.com/v1"

        url = f"{base.rstrip('/')}/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": message})

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": 4096,
        }

        response = self.client.post(url, headers=headers, json=payload)
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

    def analyze_finding(self, finding_data: dict[str, Any]) -> str:
        """Analyze a finding and provide AI insights."""
        system_prompt = """You are a penetration testing expert. Analyze the finding and provide:
1. A clear explanation of the vulnerability
2. Potential impact and risk
3. Remediation steps
Be concise and technical."""

        message = f"Analyze this finding:\n\n{str(finding_data)}"
        return self.chat(message, system_prompt)

    def suggest_next_steps(self, current_phase: str, findings: list[dict[str, Any]]) -> str:
        """Suggest next steps in the pentest based on current state."""
        system_prompt = """You are a penetration testing strategist. Based on the current phase and findings, suggest the next logical steps in the kill chain. Be specific and actionable."""

        message = f"Current phase: {current_phase}\n\nFindings so far:\n{str(findings)}\n\nWhat should I do next?"
        return self.chat(message, system_prompt)
