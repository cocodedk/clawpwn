"""Configuration management for ClawPwn.

Supports multiple configuration sources in order of priority:
1. Environment variables (highest priority)
2. Project .env file (.clawpwn/.env)
3. Global config file (~/.clawpwn/config.yml)
4. Default values (lowest priority)
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any
import yaml


def load_env_file(env_path: Path) -> Dict[str, str]:
    """Load environment variables from .env file."""
    env_vars = {}
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    # Remove quotes if present
                    value = value.strip().strip("\"'")
                    env_vars[key] = value
    return env_vars


def load_global_config() -> Dict[str, Any]:
    """Load global configuration from ~/.clawpwn/config.yml."""
    config_path = Path.home() / ".clawpwn" / "config.yml"
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    return {}


def load_project_config(project_dir: Optional[Path] = None) -> Dict[str, str]:
    """Load project-specific configuration from .env file."""
    if project_dir is None:
        # Try to find project directory
        from clawpwn.cli import get_project_dir

        project_dir = get_project_dir()

    if project_dir:
        env_path = project_dir / ".clawpwn" / ".env"
        return load_env_file(env_path)

    return {}


def get_config(
    key: str, project_dir: Optional[Path] = None, default: Any = None
) -> Any:
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


def get_api_key(
    provider: str = "anthropic", project_dir: Optional[Path] = None
) -> Optional[str]:
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


def get_llm_provider(project_dir: Optional[Path] = None) -> str:
    """Get LLM provider (default: anthropic)."""
    return get_config("CLAWPWN_LLM_PROVIDER", project_dir, default="anthropic")


def get_llm_model(project_dir: Optional[Path] = None) -> Optional[str]:
    """Get LLM model name."""
    return get_config("CLAWPWN_LLM_MODEL", project_dir)


def get_llm_base_url(project_dir: Optional[Path] = None) -> Optional[str]:
    """Get LLM base URL."""
    return get_config("CLAWPWN_LLM_BASE_URL", project_dir)


def create_project_config_template(project_dir: Path) -> Path:
    """Create a .env template file in the project directory."""
    env_path = project_dir / ".clawpwn" / ".env"

    if not env_path.exists():
        template = """# ClawPwn LLM Configuration
# Uncomment and fill in your values

# Provider: anthropic | openai | openrouter | local
# CLAWPWN_LLM_PROVIDER=anthropic

# API key for the selected provider
# CLAWPWN_LLM_API_KEY=your-api-key-here

# Base URL for self-hosted providers (optional)
# CLAWPWN_LLM_BASE_URL=https://api.example.com/v1

# Model name (provider-specific)
# CLAWPWN_LLM_MODEL=claude-3-5-sonnet-20241022

# Backward-compatible provider-specific keys (optional)
# ANTHROPIC_API_KEY=your-api-key-here
# OPENAI_API_KEY=your-api-key-here
# OPENROUTER_API_KEY=your-api-key-here
"""
        env_path.write_text(template)

    return env_path


def create_global_config() -> Path:
    """Create global config directory and file if they don't exist."""
    config_dir = Path.home() / ".clawpwn"
    config_dir.mkdir(exist_ok=True)

    config_path = config_dir / "config.yml"
    if not config_path.exists():
        default_config = {
            "ai": {
                "provider": "anthropic",
                "model": "claude-3-5-sonnet-20241022",
            },
            "scan": {
                "default_depth": "normal",
                "timeout": 30.0,
            },
            "report": {
                "default_format": "html",
                "include_evidence": True,
            },
        }
        with open(config_path, "w") as f:
            yaml.dump(default_config, f, default_flow_style=False)

    return config_path


# Initialize global config on module load
_config_initialized = False


def init_config():
    """Initialize global configuration if not already done."""
    global _config_initialized
    if not _config_initialized:
        create_global_config()
        _config_initialized = True


# Auto-init
init_config()
