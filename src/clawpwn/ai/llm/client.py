"""Core LLM client class."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx

from clawpwn.config import (
    get_llm_base_url,
    get_llm_model,
    get_llm_provider,
)

# Default models per tier
ROUTING_MODEL_DEFAULT = "claude-haiku-4-5-20251001"
ANALYSIS_MODEL_DEFAULT = "claude-haiku-4-5-20251001"


class LLMClient:
    """Client for interacting with LLM APIs (Claude, GPT-4, etc.)."""

    def __init__(
        self,
        provider: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        project_dir: Path | None = None,
    ):
        self._provider_explicit = provider is not None
        self.provider = (provider or get_llm_provider(project_dir)).lower()
        self.project_dir = project_dir

        # Get API key from multiple sources
        if api_key:
            self.api_key = api_key
        else:
            from .api_helpers import get_api_key_with_fallback

            self.api_key = get_api_key_with_fallback(self)

        # Default models
        self.model = (
            model
            or get_llm_model(project_dir)
            or {
                "anthropic": "claude-sonnet-4-5-20250929",
                "openai": "gpt-4o",
                "openrouter": "openai/gpt-4o-mini",
            }.get(self.provider, "claude-sonnet-4-5-20250929")
        )

        self.base_url = get_llm_base_url(project_dir)
        self.routing_model = os.environ.get("CLAWPWN_LLM_ROUTING_MODEL", ROUTING_MODEL_DEFAULT)

        self.client = httpx.Client(timeout=60.0)
        self._anthropic_client: Any = None  # lazy-init SDK client

    @property
    def anthropic_sdk(self) -> Any:
        """Lazy-initialised Anthropic SDK client."""
        if self._anthropic_client is None:
            import anthropic

            kwargs: dict[str, Any] = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self._anthropic_client = anthropic.Anthropic(**kwargs)
        return self._anthropic_client

    def close(self) -> None:
        """Close the underlying HTTP client and release the connection pool."""
        client = getattr(self, "client", None)
        if client is not None:
            client.close()
            self.client = None
        sdk = getattr(self, "_anthropic_client", None)
        if sdk is not None:
            sdk.close()
            self._anthropic_client = None

    def __enter__(self) -> LLMClient:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def chat(self, message: str, system_prompt: str | None = None, model: str | None = None) -> str:
        """Send a chat message and get a response.

        Args:
            message: The user message to send.
            system_prompt: Optional system prompt.
            model: Override the default model for this call (e.g. routing_model).
        """
        if self.provider == "anthropic":
            from .anthropic_impl import chat_anthropic

            return chat_anthropic(self, message, system_prompt, model=model)
        elif self.provider in ("openai", "openrouter"):
            from .openai_impl import chat_openai

            return chat_openai(self, message, system_prompt, model=model)
        else:
            raise ValueError(f"Unknown provider: {self.provider}")

    def analyze_finding(self, finding_data: dict[str, Any]) -> str:
        """Analyze a finding and provide AI insights."""
        from .analysis import analyze_finding

        return analyze_finding(self, finding_data)

    def suggest_next_steps(self, current_phase: str, findings: list[dict[str, Any]]) -> str:
        """Suggest next steps in the pentest based on current state."""
        from .analysis import suggest_next_steps

        return suggest_next_steps(self, current_phase, findings)
