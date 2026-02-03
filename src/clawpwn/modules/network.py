"""Network discovery module for ClawPwn."""

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

from clawpwn.tools.nmap import NmapScanner, HostResult, PortScanResult
from clawpwn.modules.session import SessionManager


@dataclass
class ServiceInfo:
    """Represents a discovered service."""

    port: int
    protocol: str
    name: str
    version: str
    product: str
    banner: str = ""
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class HostInfo:
    """Complete information about a discovered host."""

    ip: str
    hostname: str = ""
    os: str = ""
    services: List[ServiceInfo] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    notes: str = ""


class NetworkDiscovery:
    """Manages network discovery and host enumeration."""

    def __init__(self, project_dir: Optional[Path] = None):
        self.scanner = NmapScanner()
        self.project_dir = project_dir
        self.session: Optional[SessionManager] = None

        if project_dir:
            db_path = project_dir / ".clawpwn" / "clawpwn.db"
            if db_path.exists():
                self.session = SessionManager(db_path)

    async def discover_hosts(self, network: str) -> List[str]:
        """
        Discover live hosts on a network.

        Args:
            network: Network range (e.g., "192.168.1.0/24")

        Returns:
            List of live IP addresses
        """
        print(f"[*] Discovering hosts on {network}...")
        hosts = await self.scanner.ping_sweep(network)
        print(f"[+] Found {len(hosts)} live hosts")
        return hosts

    async def scan_host(
        self, target: str, scan_type: str = "quick", full_scan: bool = False
    ) -> HostInfo:
        """
        Scan a single host for open ports and services.

        Args:
            target: IP address or hostname
            scan_type: "quick", "normal", or "full"
            full_scan: Scan all 65535 ports
        """
        print(f"[*] Scanning {target}...")

        if full_scan or scan_type == "full":
            results = await self.scanner.full_scan(target)
        elif scan_type == "quick":
            results = await self.scanner.quick_scan(target)
        else:
            results = await self.scanner.scan_host(target, version_detection=True)

        if not results:
            return HostInfo(ip=target, notes="No response from host")

        host_result = results[0]

        # Convert to HostInfo
        host_info = HostInfo(
            ip=host_result.ip,
            hostname=host_result.hostname,
            os=host_result.os_info.get("name", ""),
        )

        # Process ports
        for port in host_result.ports:
            if port.state == "open":
                host_info.open_ports.append(port.port)

                service = ServiceInfo(
                    port=port.port,
                    protocol=port.protocol,
                    name=port.service,
                    version=port.version,
                    product=port.product,
                    banner=f"{port.product} {port.version}".strip(),
                )
                host_info.services.append(service)

        # Log the discovery
        if self.session:
            self.session.add_log(
                f"Discovered host {target}: {len(host_info.open_ports)} open ports",
                phase="Reconnaissance",
            )

        print(f"[+] {target}: {len(host_info.open_ports)} open ports")
        return host_info

    async def enumerate_target(self, target: str) -> Dict[str, Any]:
        """
        Full enumeration of a target.

        Returns:
            Dictionary with all enumeration results
        """
        results = {
            "target": target,
            "hosts": [],
            "services": [],
            "web_services": [],
        }

        # Scan the target
        host_info = await self.scan_host(target, scan_type="normal")
        results["hosts"].append(host_info)

        # Identify interesting services
        for service in host_info.services:
            service_data = {
                "port": service.port,
                "name": service.name,
                "version": service.version,
                "product": service.product,
            }
            results["services"].append(service_data)

            # Check for web services
            if service.name in ["http", "https", "http-proxy"]:
                results["web_services"].append(
                    {
                        "url": f"{'https' if service.port == 443 else 'http'}://{target}:{service.port}",
                        "port": service.port,
                        "service": service.name,
                    }
                )

        return results

    def print_summary(self, results: Dict[str, Any]) -> None:
        """Print a summary of discovery results."""
        print("\n" + "=" * 60)
        print("NETWORK DISCOVERY SUMMARY")
        print("=" * 60)

        for host in results.get("hosts", []):
            print(f"\nHost: {host.ip} ({host.hostname or 'unknown'})")
            print(f"OS: {host.os or 'unknown'}")

            if host.services:
                print("\nOpen Ports:")
                for service in host.services:
                    banner = f" - {service.banner}" if service.banner else ""
                    print(
                        f"  {service.port}/{service.protocol}: {service.name}{banner}"
                    )

        web_services = results.get("web_services", [])
        if web_services:
            print("\nWeb Services Found:")
            for web in web_services:
                print(f"  {web['url']}")

        print("=" * 60)


# Convenience function for quick scans
async def quick_scan(target: str) -> HostInfo:
    """Quick scan of a target."""
    discovery = NetworkDiscovery()
    return await discovery.scan_host(target, scan_type="quick")
