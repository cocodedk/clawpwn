"""Interactive configuration prompts and utilities."""

import getpass
import os
import sys
from pathlib import Path

from .env_loader import load_env_file

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


def init_config():
    """Initialize global configuration if not already done."""
    from .project_setup import create_global_config

    global _config_initialized
    if not _config_initialized:
        create_global_config()
        _config_initialized = True


# Initialize global config on module load
_config_initialized = False
init_config()
