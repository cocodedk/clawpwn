"""Shared CLI app objects and project helpers."""

import socket
import ssl
import tempfile
from pathlib import Path

import typer
from rich.console import Console

from clawpwn.config import is_global_config_dir
from clawpwn.modules.network import ServiceInfo

app = typer.Typer(
    name="clawpwn",
    help="AI-powered penetration testing tool",
    no_args_is_help=True,
)
console = Console()

# Top common UDP ports for fast default scan (DNS, DHCP, NTP, SNMP, etc.)
UDP_TOP_PORTS = "53,67,68,69,123,137,138,139,161,162,500,514,520,631,1434,1900,4500,5353"


def detect_scheme(host: str, port: int, service: ServiceInfo, timeout: float = 2.0) -> str:
    """Derive URL scheme from service metadata or TLS probe."""
    name = (service.name or "").lower()
    protocol = (service.protocol or "").lower()
    if name == "https" or "https" in name or "tls" in protocol or "ssl" in protocol:
        return "https"

    try:
        ctx = ssl.create_default_context()
        # Probe only; accept invalid certs to avoid false HTTP classification.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as _:
                return "https"
    except (OSError, ssl.SSLError):
        return "http"


def get_project_dir() -> Path | None:
    """Find the project directory by looking for a .clawpwn marker.

    Stops walking at the system temp root (e.g. ``/tmp``) to avoid
    matching stale ``.clawpwn`` dirs left by test runs or throwaway work.
    """
    current = Path.cwd()
    try:
        temp_root = Path(tempfile.gettempdir()).resolve()
    except OSError:
        temp_root = None
    while current != current.parent:
        if temp_root and current.resolve() == temp_root:
            return None
        marker = current / ".clawpwn"
        if marker.exists():
            if (
                marker.is_dir()
                and is_global_config_dir(marker)
                and not (marker / "clawpwn.db").exists()
            ):
                current = current.parent
                continue
            return current
        current = current.parent
    return None


def require_project() -> Path:
    """Ensure the current directory is inside a ClawPwn project."""
    project_dir = get_project_dir()
    if project_dir:
        return project_dir

    home_marker = Path.home() / ".clawpwn"
    if (
        home_marker.is_dir()
        and is_global_config_dir(home_marker)
        and not (home_marker / "clawpwn.db").exists()
    ):
        console.print(
            "[yellow]Note:[/yellow] ~/.clawpwn is a global config folder, not a project marker."
        )
    console.print("[red]Error: Not in a clawpwn project. Run 'clawpwn init' first.[/red]")
    raise typer.Exit(1)
