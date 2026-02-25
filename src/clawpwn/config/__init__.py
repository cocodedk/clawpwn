"""
Configuration management for ClawPwn.

Supports multiple configuration sources in order of priority:
1. Environment variables (highest priority)
2. Project .env file (.clawpwn/.env)
3. Global config file (~/.clawpwn/config.yml)
4. Default values (lowest priority)
"""

# Re-export all public APIs for backward compatibility
from .env_loader import (
    is_global_config_dir,
    load_env_file,
    load_global_config,
    load_project_config,
)
from .getters import (
    get_api_key,
    get_config,
    get_llm_base_url,
    get_llm_model,
    get_llm_provider,
)
from .interactive import (
    ENV_KEYS,
    ENV_PROMPTS,
    LLM_REQUIRED_KEYS,
    ensure_env_file,
    init_config,
    write_env_file,
)
from .project_setup import (
    create_global_config,
    create_project_config_template,
    ensure_project_env,
    ensure_project_storage_dir,
    get_project_db_path,
    get_project_env_path,
    get_project_storage_dir,
)

__all__ = [
    # env_loader
    "is_global_config_dir",
    "load_env_file",
    "load_global_config",
    "load_project_config",
    # getters
    "get_api_key",
    "get_config",
    "get_llm_base_url",
    "get_llm_model",
    "get_llm_provider",
    # interactive
    "ENV_KEYS",
    "ENV_PROMPTS",
    "LLM_REQUIRED_KEYS",
    "ensure_env_file",
    "init_config",
    "write_env_file",
    # project_setup
    "create_global_config",
    "create_project_config_template",
    "ensure_project_env",
    "ensure_project_storage_dir",
    "get_project_db_path",
    "get_project_env_path",
    "get_project_storage_dir",
]
