"""Tools package for ClawPwn."""

from typing import Any, List, Protocol

from clawpwn.tools.masscan import HostResult, MasscanScanner, PortScanResult
from clawpwn.tools.nmap import NmapScanner
from clawpwn.tools.rustscan import RustScanScanner


class BaseScanner(Protocol):
    """Protocol for port scanners used by NetworkDiscovery."""

    async def scan_host(
        self,
        target: str,
        ports: str = "1-65535",
        **kwargs: Any,
    ) -> List[HostResult]:
        """Scan a target and return host results with open ports."""
        ...


__all__ = [
    "BaseScanner",
    "HostResult",
    "MasscanScanner",
    "NmapScanner",
    "PortScanResult",
    "RustScanScanner",
]
