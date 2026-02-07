"""Configuration getter functions."""

import os
from pathlib import Path
from typing import Any

from .env_loader import load_global_config, load_project_config


def get_config(key: str, project_dir: Path | None = None, default: Any = None) -> Any:
    """
    Get configuration value with priority:
    1. Environment variable
    2. Project .env file
    3. Global config file
    4. Default value

    Args:
        key: Configuration key
        project_dir: Optional project directory
        default: Default value if not found

    Returns:
        Configuration value or default
    """
    # 1. Check environment variable
    env_value = os.environ.get(key)
    if env_value:
        return env_value

    # 2. Check project .env file
    project_config = load_project_config(project_dir)
    if key in project_config:
        return project_config[key]

    # 3. Check global config
    global_config = load_global_config()
    if key in global_config:
        return global_config[key]

    # 4. Return default
    return default


def get_api_key(provider: str = "anthropic", project_dir: Path | None = None) -> str | None:
    """
    Get API key for a provider.

    Args:
        provider: Provider name (anthropic, openai)
        project_dir: Optional project directory

    Returns:
        API key or None if not found
    """
    # New unified key (preferred)
    unified = get_config("CLAWPWN_LLM_API_KEY", project_dir)
    if unified:
        return unified

    # Backward-compatible provider-specific keys
    env_var = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
    }.get(provider, f"{provider.upper()}_API_KEY")

    return get_config(env_var, project_dir)


def get_llm_provider(project_dir: Path | None = None) -> str:
    """Get LLM provider (default: anthropic)."""
    return get_config("CLAWPWN_LLM_PROVIDER", project_dir, default="anthropic")


def get_llm_model(project_dir: Path | None = None) -> str | None:
    """Get LLM model name."""
    return get_config("CLAWPWN_LLM_MODEL", project_dir)


def get_llm_base_url(project_dir: Path | None = None) -> str | None:
    """Get LLM base URL."""
    return get_config("CLAWPWN_LLM_BASE_URL", project_dir)
