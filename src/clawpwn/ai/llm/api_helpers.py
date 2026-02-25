"""API key fallback logic and error formatting."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from clawpwn.config import (
    ensure_project_env,
    get_api_key,
    get_llm_provider,
    get_project_env_path,
)

if TYPE_CHECKING:
    from .client import LLMClient


def get_api_key_with_fallback(client: LLMClient) -> str:
    """Get API key from multiple sources with helpful error messages."""
    api_key = get_api_key(client.provider, client.project_dir)

    if not api_key and client.project_dir:
        ensure_project_env(client.project_dir)
        if not client._provider_explicit:
            client.provider = get_llm_provider(client.project_dir).lower()
        api_key = get_api_key(client.provider, client.project_dir)

    if not api_key:
        # Create helpful error message with setup instructions
        env_var = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
        }.get(client.provider, f"{client.provider.upper()}_API_KEY")

        env_path = (
            get_project_env_path(client.project_dir)
            if client.project_dir
            else Path(".clawpwn/.env")
        )

        error_msg = f"""API key not found for provider: {client.provider}

To set your API key, choose one of these methods:

1. Environment variable (quick):
   export CLAWPWN_LLM_API_KEY=your-api-key
   export CLAWPWN_LLM_PROVIDER={client.provider}
   # or legacy: export {env_var}=your-api-key

2. Project .env file (recommended per project):
   echo "CLAWPWN_LLM_PROVIDER={client.provider}" >> {env_path}
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
