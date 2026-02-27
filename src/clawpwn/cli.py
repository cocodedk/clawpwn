"""ClawPwn CLI public facade."""

from clawpwn.config import (
    create_global_config,
    create_project_config_template,
    ensure_project_storage_dir,
    get_project_db_path,
    get_project_env_path,
    is_global_config_dir,
    load_global_config,
    load_project_config,
)
from clawpwn.modules.network import HostInfo, NetworkDiscovery, ServiceInfo
from clawpwn.modules.scanner import ScanConfig, Scanner
from clawpwn.modules.session import SessionManager
from clawpwn.utils.async_utils import safe_async_run

from .cli_commands.autopilot_command import autopilot
from .cli_commands.config_command import config
from .cli_commands.console_command import console_cmd, interactive
from .cli_commands.discover_command import discover
from .cli_commands.doctor_command import doctor
from .cli_commands.experience_command import experience
from .cli_commands.killchain_command import killchain
from .cli_commands.memory_command import memory, objective
from .cli_commands.project_init import init
from .cli_commands.project_state import list_projects, status, target, version
from .cli_commands.recon_command import recon
from .cli_commands.report_logs_command import logs, report
from .cli_commands.scan_command import scan
from .cli_commands.shared import app, console, detect_scheme, get_project_dir, require_project

_detect_scheme = detect_scheme

__all__ = [
    "app",
    "autopilot",
    "console",
    "config",
    "console_cmd",
    "create_global_config",
    "create_project_config_template",
    "discover",
    "doctor",
    "ensure_project_storage_dir",
    "experience",
    "get_project_db_path",
    "get_project_dir",
    "get_project_env_path",
    "HostInfo",
    "init",
    "interactive",
    "is_global_config_dir",
    "killchain",
    "list_projects",
    "logs",
    "main",
    "memory",
    "NetworkDiscovery",
    "objective",
    "recon",
    "load_global_config",
    "load_project_config",
    "report",
    "require_project",
    "safe_async_run",
    "ScanConfig",
    "scan",
    "Scanner",
    "ServiceInfo",
    "SessionManager",
    "status",
    "target",
    "version",
]


def main() -> None:
    """Entry point for the CLI."""
    app()
