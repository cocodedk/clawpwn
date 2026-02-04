"""
Configuration management for ClawPwn.

Supports multiple configuration sources in order of priority:
1. Environment variables (highest priority)
2. Project .env file (.clawpwn/.env)
3. Global config file (~/.clawpwn/config.yml)
4. Default values (lowest priority)
"""

import getpass
import hashlib
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

ENV_KEYS = (
    "CLAWPWN_LLM_PROVIDER",
    "CLAWPWN_LLM_API_KEY",
    "CLAWPWN_LLM_BASE_URL",
    "CLAWPWN_LLM_MODEL",
    "CLAWPWN_DATA_DIR",
    "CLAWPWN_VERBOSE",
)

ENV_PROMPTS = {
    "CLAWPWN_LLM_PROVIDER": ("LLM provider (e.g., openai, anthropic, local)", False),
    "CLAWPWN_LLM_API_KEY": ("LLM API key", True),
    "CLAWPWN_LLM_BASE_URL": ("LLM base URL (optional)", False),
    "CLAWPWN_LLM_MODEL": ("Default model (e.g., gpt-4.1)", False),
    "CLAWPWN_DATA_DIR": ("Data directory (optional, leave blank for default)", False),
    "CLAWPWN_VERBOSE": ("Verbose logging (true/false)", False),
}

LLM_REQUIRED_KEYS = ("CLAWPWN_LLM_PROVIDER", "CLAWPWN_LLM_API_KEY")


def is_global_config_dir(path: Path) -> bool:
    """Return True if the path is the global ~/.clawpwn config directory."""
    home_config = Path.home() / ".clawpwn"
    try:
        return path.resolve() == home_config.resolve()
    except FileNotFoundError:
        return path == home_config


def load_env_file(env_path: Path) -> dict[str, str]:
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


def load_global_config() -> dict[str, Any]:
    """Load global configuration from ~/.clawpwn/config.yml."""
    config_path = Path.home() / ".clawpwn" / "config.yml"
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    return {}


def _sanitize_env_value(value: str) -> str:
    value = value.replace("\n", "").replace("\r", "")
    return value


def _merge_current_env_values(
    current: dict[str, str],
    env_path: Path | None = None,
    alt_env_path: Path | None = None,
) -> dict[str, str]:
    merged = dict(current)
    if env_path and env_path.exists():
        merged.update(load_env_file(env_path))
    if alt_env_path and alt_env_path.exists():
        merged.update(load_env_file(alt_env_path))
    # Prefer process environment if not already set.
    for key in ENV_KEYS:
        if not merged.get(key):
            env_val = os.environ.get(key)
            if env_val:
                merged[key] = env_val
    return merged


def _prompt_value(key: str, prompt: str, secret: bool, current: str) -> str:
    if current:
        print(f"  Current value: {current}", file=sys.stderr)
    else:
        print("  Current value: (empty)", file=sys.stderr)
    print(
        "  (Press Enter to keep current value, or enter a new value. "
        "If current is empty, you must enter a value to set one.)",
        file=sys.stderr,
    )
    if secret:
        value = getpass.getpass(f"{prompt}: ")
    else:
        value = input(f"{prompt}: ")
    if not value and current:
        return current
    return value


def _prompt_env_values(current: dict[str, str]) -> dict[str, str]:
    values: dict[str, str] = {}
    provider_current = current.get("CLAWPWN_LLM_PROVIDER", "")
    prompt, secret = ENV_PROMPTS["CLAWPWN_LLM_PROVIDER"]
    provider_value = _prompt_value("CLAWPWN_LLM_PROVIDER", prompt, secret, provider_current)
    provider_value = _sanitize_env_value(provider_value)
    values["CLAWPWN_LLM_PROVIDER"] = provider_value

    for key in ENV_KEYS:
        if key == "CLAWPWN_LLM_PROVIDER":
            continue
        prompt, secret = ENV_PROMPTS[key]
        if key == "CLAWPWN_LLM_BASE_URL" and provider_value.lower() == "openrouter":
            val = "https://openrouter.ai/api/v1"
            print(f"  Using OpenRouter base URL: {val}", file=sys.stderr)
        else:
            current_val = current.get(key, "")
            val = _prompt_value(key, prompt, secret, current_val)
        values[key] = _sanitize_env_value(val)

    return values


def write_env_file(env_path: Path, values: dict[str, str]) -> None:
    """Write a .env file with the given values."""
    env_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{key}={values.get(key, '')}" for key in ENV_KEYS]
    env_path.write_text("\n".join(lines) + "\n")


def ensure_env_file(
    env_path: Path,
    required_keys: tuple[str, ...] = LLM_REQUIRED_KEYS,
    *,
    force: bool = False,
    interactive: bool | None = None,
    alt_env_path: Path | None = None,
) -> bool:
    """
    Ensure a .env file exists and contains required keys.

    Returns True if the file was created or updated.
    """
    if interactive is None:
        interactive = sys.stdin.isatty()
    if not interactive:
        return False

    current = _merge_current_env_values({}, env_path=env_path, alt_env_path=alt_env_path)

    need_prompt = force or (not env_path.exists())
    if not need_prompt:
        for key in required_keys:
            if not current.get(key):
                need_prompt = True
                break

    if not need_prompt:
        return False

    if alt_env_path and alt_env_path.exists() and not env_path.exists():
        print(
            f"Found {alt_env_path}, but ClawPwn uses {env_path} per project.",
            file=sys.stderr,
        )

    values = _prompt_env_values(current)
    write_env_file(env_path, values)
    return True


def load_project_config(project_dir: Path | None = None) -> dict[str, str]:
    """Load project-specific configuration from .env file."""
    if project_dir is None:
        # Try to find project directory
        from clawpwn.cli import get_project_dir

        project_dir = get_project_dir()

    if project_dir:
        env_path = get_project_env_path(project_dir)
        if env_path:
            return load_env_file(env_path)

    return {}


def _storage_name(project_dir: Path) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", project_dir.name).strip("-") or "project"
    digest = hashlib.sha1(str(project_dir).encode()).hexdigest()[:8]
    return f"{slug}-{digest}"


def get_project_storage_dir(project_dir: Path | None) -> Path | None:
    """Resolve the storage directory for a project (.clawpwn or data dir)."""
    if project_dir is None:
        return None

    marker = project_dir / ".clawpwn"
    if marker.is_file():
        try:
            target = marker.read_text().strip()
            if target:
                return Path(target)
        except (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError) as e:
            logger.warning(
                "Could not read project storage path from marker %s: %s",
                marker,
                e,
                exc_info=True,
            )
            return None

    if marker.is_dir():
        # Avoid treating the global ~/.clawpwn config dir as a project marker.
        if is_global_config_dir(marker) and not (marker / "clawpwn.db").exists():
            return None
        return marker

    data_root = os.environ.get("CLAWPWN_DATA_DIR")
    if data_root:
        return Path(data_root) / _storage_name(project_dir)

    return marker


def ensure_project_storage_dir(project_dir: Path) -> Path:
    """Ensure the project storage directory exists and return it."""
    marker = project_dir / ".clawpwn"
    if marker.is_dir():
        return marker

    if marker.is_file():
        target = marker.read_text().strip()
        if not target:
            raise ValueError("Project marker file is empty.")
        storage = Path(target)
        storage.mkdir(parents=True, exist_ok=True)
        return storage

    storage = get_project_storage_dir(project_dir)
    if storage is None:
        raise ValueError("Unable to resolve project storage directory.")

    storage.mkdir(parents=True, exist_ok=True)

    # If using a data dir, create marker file in project dir
    if storage != marker:
        marker.write_text(str(storage))
    else:
        marker.mkdir(exist_ok=True)

    return storage


def get_project_db_path(project_dir: Path | None) -> Path | None:
    """Get the project database path."""
    storage = get_project_storage_dir(project_dir)
    if storage is None:
        return None
    return storage / "clawpwn.db"


def get_project_env_path(project_dir: Path | None) -> Path | None:
    """Get the project .env path."""
    storage = get_project_storage_dir(project_dir)
    if storage is None:
        return None
    return storage / ".env"


def ensure_project_env(
    project_dir: Path,
    *,
    force: bool = False,
    interactive: bool | None = None,
) -> Path | None:
    """Ensure the per-project .env exists; prompt to create if missing."""
    env_path = get_project_env_path(project_dir)
    if env_path is None:
        return None
    alt_env_path = project_dir / ".env"
    use_alt = alt_env_path if alt_env_path.exists() and not env_path.exists() else None
    ensure_env_file(
        env_path,
        required_keys=LLM_REQUIRED_KEYS,
        force=force,
        interactive=interactive,
        alt_env_path=use_alt,
    )
    return env_path


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


def create_project_config_template(project_dir: Path) -> Path:
    """Create a .env template file in the project directory."""
    storage_dir = ensure_project_storage_dir(project_dir)
    env_path = storage_dir / ".env"

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

# Masscan configuration
# CLAWPWN_MASSCAN_RATE=10000
# CLAWPWN_MASSCAN_PORTS_QUICK=1-1024
# CLAWPWN_MASSCAN_PORTS_NORMAL=1-10000
# CLAWPWN_MASSCAN_PORTS_DEEP=1-65535
# CLAWPWN_MASSCAN_PORTS_TCP=1-65535
# CLAWPWN_MASSCAN_PORTS_UDP=1-65535
# CLAWPWN_MASSCAN_INTERFACE=eth0
# CLAWPWN_MASSCAN_SUDO=true

# Vulnerability lookup (service-name + version)
# CLAWPWN_VULN_LOOKUP=true
# CLAWPWN_VULN_MAX_RESULTS=3

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
