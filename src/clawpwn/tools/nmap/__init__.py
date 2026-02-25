"""Nmap wrapper for network discovery."""

import asyncio

from .privileges import _can_sudo_without_password, _is_root, _needs_sudo
from .scanner import HostResult, NmapScanner, PortScanResult
from .xml_parser import parse_nmap_xml

__all__ = [
    "HostResult",
    "NmapScanner",
    "PortScanResult",
    "parse_nmap_xml",
    "test_nmap",
    "_is_root",
    "_can_sudo_without_password",
    "_needs_sudo",
]


# Add convenience methods to NmapScanner
async def _quick_scan(self, target: str, verbose: bool = False) -> list[HostResult]:
    """Quick scan of top 1000 ports."""
    return await self.scan_host(target, aggressive=True, version_detection=True, verbose=verbose)


async def _full_scan(self, target: str, verbose: bool = False) -> list[HostResult]:
    """Full scan of all ports with version detection."""
    return await self.scan_host(
        target,
        ports="1-65535",
        aggressive=True,
        version_detection=True,
        script_scan=True,
        verbose=verbose,
    )


async def _scan_host_tcp_connect(
    self,
    target: str,
    ports: str,
    version_detection: bool = True,
    verbose: bool = False,
) -> list[HostResult]:
    """TCP connect scan for specific ports."""
    return await self.scan_host(
        target,
        ports=ports,
        aggressive=True,
        version_detection=version_detection,
        tcp_connect=True,
        verbose=verbose,
    )


async def _scan_host_udp(self, target: str, ports: str, verbose: bool = False) -> list[HostResult]:
    """UDP scan for specific ports."""
    return await self.scan_host(
        target,
        ports=ports,
        aggressive=False,
        version_detection=False,
        udp=True,
        verbose=verbose,
    )


# Monkey-patch convenience methods onto NmapScanner
NmapScanner.quick_scan = _quick_scan
NmapScanner.full_scan = _full_scan
NmapScanner.scan_host_tcp_connect = _scan_host_tcp_connect
NmapScanner.scan_host_udp = _scan_host_udp


async def test_nmap():
    """Test the nmap scanner."""
    scanner = NmapScanner()
    results = await scanner.quick_scan("127.0.0.1")
    for host in results:
        print(f"Host: {host.ip} ({host.hostname})")
        for port in host.ports:
            print(
                f"  Port {port.port}/{port.protocol}: {port.service} {port.product} {port.version}"
            )


if __name__ == "__main__":
    asyncio.run(test_nmap())
