"""Environment variable and configuration file loading."""

from pathlib import Path
from typing import Any

import yaml


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


def load_project_config(project_dir: Path | None = None) -> dict[str, str]:
    """Load project-specific configuration from .env file."""
    if project_dir is None:
        # Try to find project directory
        from clawpwn.cli import get_project_dir

        project_dir = get_project_dir()

    if project_dir:
        from clawpwn.config.project_setup import get_project_env_path

        env_path = get_project_env_path(project_dir)
        if env_path:
            return load_env_file(env_path)

    return {}
