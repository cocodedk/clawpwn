"""Network discovery module for ClawPwn."""

import os as _os
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from clawpwn.config import get_project_db_path
from clawpwn.modules.network_parts.operations_mixin import OperationsMixin
from clawpwn.modules.network_parts.scanner_mixin import ScannerMixin
from clawpwn.modules.network_parts.task_mixin import TaskMixin
from clawpwn.modules.session import SessionManager
from clawpwn.modules.vulndb import VulnDBClient
from clawpwn.tools.masscan import HostResult, MasscanScanner, PortScanResult
from clawpwn.tools.naabu import NaabuScanner
from clawpwn.tools.nmap import NmapScanner
from clawpwn.tools.rustscan import RustScanScanner
from clawpwn.utils.privileges import can_raw_scan, get_privilege_help

console = Console()
os_environ = _os.environ

__all__ = [
    "HostInfo",
    "HostResult",
    "MasscanScanner",
    "NaabuScanner",
    "NetworkDiscovery",
    "NmapScanner",
    "PortScanResult",
    "RustScanScanner",
    "ServiceInfo",
    "VulnDBClient",
    "_parse_port_spec",
    "_split_port_range",
    "can_raw_scan",
    "console",
    "get_privilege_help",
    "quick_scan",
]


@dataclass
class ServiceInfo:
    """Represents a discovered service."""

    port: int
    protocol: str
    name: str
    version: str
    product: str
    banner: str = ""
    vulnerabilities: list[str] = field(default_factory=list)


@dataclass
class HostInfo:
    """Complete information about a discovered host."""

    ip: str
    hostname: str = ""
    os: str = ""
    services: list[ServiceInfo] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    notes: str = ""


def _split_port_range(low: int, high: int, n: int) -> list[str]:
    """Split a port range [low, high] into n roughly equal range strings."""
    if n <= 1 or high <= low:
        return [f"{low}-{high}"]
    total = high - low + 1
    chunk_size = max(1, total // n)
    ranges: list[str] = []
    start = low
    for _ in range(n - 1):
        end = min(start + chunk_size - 1, high)
        ranges.append(f"{start}-{end}")
        start = end + 1
    if start <= high:
        ranges.append(f"{start}-{high}")
    return ranges


def _parse_port_spec(spec: str) -> tuple[int, int] | None:
    """Parse 'a-b' into (a, b). Returns None for comma-separated or single ports."""
    spec = spec.strip()
    if "-" in spec and "," not in spec:
        parts = spec.split("-", 1)
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            return int(parts[0]), int(parts[1])
    return None


class NetworkDiscovery(ScannerMixin, TaskMixin, OperationsMixin):
    """Manages network discovery and host enumeration."""

    def __init__(self, project_dir: Path | None = None):
        self._port_scanner: MasscanScanner | NaabuScanner | NmapScanner | RustScanScanner | None = (
            None
        )
        self._scanner_type: str = "rustscan"
        self.nmap: NmapScanner | None = None
        self.project_dir = project_dir
        self.session: SessionManager | None = None

        if project_dir:
            db_path = get_project_db_path(project_dir)
            if db_path and db_path.exists():
                self.session = SessionManager(db_path)


async def quick_scan(target: str) -> HostInfo:
    """Quick scan of a target."""
    discovery = NetworkDiscovery()
    return await discovery.scan_host(target, scan_type="quick")
