"""Project storage directory and environment setup."""

import hashlib
import logging
import os
import re
from pathlib import Path

from .env_loader import is_global_config_dir

logger = logging.getLogger(__name__)


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
    from .interactive import LLM_REQUIRED_KEYS, ensure_env_file

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
    import yaml

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
