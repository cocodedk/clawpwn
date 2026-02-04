"""Network discovery module for ClawPwn."""

import asyncio
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from clawpwn.config import get_project_db_path
from clawpwn.modules.session import SessionManager
from clawpwn.tools.masscan import HostResult, MasscanScanner, PortScanResult
from clawpwn.tools.nmap import NmapScanner
from clawpwn.tools.rustscan import RustScanScanner
from clawpwn.utils.privileges import can_raw_scan, get_privilege_help


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
    a = low
    for _ in range(n - 1):
        b = min(a + chunk_size - 1, high)
        ranges.append(f"{a}-{b}")
        a = b + 1
    if a <= high:
        ranges.append(f"{a}-{high}")
    return ranges


def _parse_port_spec(spec: str) -> tuple[int, int] | None:
    """Parse 'a-b' into (a, b). Returns None for comma-separated or single ports."""
    spec = spec.strip()
    if "-" in spec and "," not in spec:
        parts = spec.split("-", 1)
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            return (int(parts[0]), int(parts[1]))
    return None


class NetworkDiscovery:
    """Manages network discovery and host enumeration."""

    def __init__(self, project_dir: Path | None = None):
        self._port_scanner: MasscanScanner | NmapScanner | RustScanScanner | None = None
        self._scanner_type: str = "rustscan"
        self.nmap: NmapScanner | None = None
        self.project_dir = project_dir
        self.session: SessionManager | None = None

        if project_dir:
            db_path = get_project_db_path(project_dir)
            if db_path and db_path.exists():
                self.session = SessionManager(db_path)

    def _get_port_scanner(self, scanner_type: str = "rustscan"):
        """Return the port scanner instance for the given type."""
        if self._port_scanner is not None and self._scanner_type == scanner_type:
            return self._port_scanner
        self._scanner_type = scanner_type
        if scanner_type == "rustscan":
            self._port_scanner = RustScanScanner()
        elif scanner_type == "masscan":
            self._port_scanner = MasscanScanner()
        elif scanner_type == "nmap":
            self._port_scanner = NmapScanner()
        else:
            raise ValueError(
                f"Unknown scanner type: {scanner_type}. Use rustscan, masscan, or nmap."
            )
        return self._port_scanner

    async def _run_port_scan(
        self,
        scanner: Any,
        scanner_type: str,
        target: str,
        ports: str,
        verbose: bool,
    ) -> list[HostResult]:
        """Run port scan with scanner-specific arguments."""
        if scanner_type in ("rustscan", "masscan") and not can_raw_scan(scanner_type):
            raise RuntimeError(get_privilege_help(scanner_type))
        if scanner_type == "rustscan":
            batch_size = int(os.environ.get("CLAWPWN_RUSTSCAN_BATCH_SIZE", "5000"))
            timeout_ms = int(os.environ.get("CLAWPWN_RUSTSCAN_TIMEOUT_MS", "1000"))
            return await scanner.scan_host(
                target,
                ports=ports,
                batch_size=batch_size,
                timeout_ms=timeout_ms,
                verbose=verbose,
            )
        if scanner_type == "masscan":
            rate = self._rate_for_scan()
            interface = os.environ.get("CLAWPWN_MASSCAN_INTERFACE")
            return await scanner.scan_host(
                target,
                ports=ports,
                rate=rate,
                interface=interface,
                sudo=False,
                verbose=verbose,
            )
        if scanner_type == "nmap":
            return await scanner.scan_host(
                target,
                ports=ports,
                verbose=verbose,
            )
        raise ValueError(f"Unknown scanner type: {scanner_type}")

    async def discover_hosts(self, network: str) -> list[str]:
        """
        Discover live hosts on a network.

        Args:
            network: Network range (e.g., "192.168.1.0/24")

        Returns:
            List of live IP addresses
        """
        print(f"[*] Discovering hosts on {network}...")
        if self.nmap is None:
            self.nmap = NmapScanner()
        hosts = await self.nmap.ping_sweep(network)
        print(f"[+] Found {len(hosts)} live hosts")
        return hosts

    def _merge_host_results(
        self, results_list: list[list[HostResult]], target: str
    ) -> list[HostResult]:
        """Merge multiple scan results for the same target into one HostResult per IP."""
        all_ports: dict[int, PortScanResult] = {}
        for results in results_list:
            for host in results:
                for port in host.ports:
                    if port.state == "open" and port.port not in all_ports:
                        all_ports[port.port] = port
        ports_sorted = [all_ports[p] for p in sorted(all_ports)]
        return [HostResult(ip=target, ports=ports_sorted)]

    async def scan_host(
        self,
        target: str,
        scan_type: str = "quick",
        full_scan: bool = False,
        verbose: bool = False,
        include_udp: bool = False,
        verify_tcp: bool = False,
        ports_tcp: str | None = None,
        ports_udp: str | None = None,
        scanner_type: str = "rustscan",
        parallel_groups: int = 4,
    ) -> HostInfo:
        """
        Scan a single host for open ports and services.

        Args:
            target: IP address or hostname
            scan_type: "quick", "normal", or "full"
            full_scan: Scan all 65535 ports
            scanner_type: "rustscan", "masscan", or "nmap"
            parallel_groups: Number of parallel port groups (for range scans only)
        """
        print(f"[*] Scanning {target}...")

        ports = ports_tcp or self._ports_for_scan(scan_type, full_scan)
        scanner = self._get_port_scanner(scanner_type)
        print(f"[*] Port scan ({scanner_type})")

        # Parallel port group scanning: only for single range (e.g. 1-65535)
        port_ranges: list[str] = []
        parsed = _parse_port_spec(ports)
        if parsed and parallel_groups > 1:
            low, high = parsed
            port_ranges = _split_port_range(low, high, parallel_groups)
        else:
            port_ranges = [ports]

        if len(port_ranges) > 1:
            tasks = [
                self._run_port_scan(scanner, scanner_type, target, pr, verbose)
                for pr in port_ranges
            ]
            results_list = await asyncio.gather(*tasks)
            results = self._merge_host_results(results_list, target)
        else:
            results = await self._run_port_scan(scanner, scanner_type, target, ports, verbose)

        # Convert to HostInfo
        host_info = HostInfo(
            ip=target,
            hostname="",
            os="",
        )

        host_result = results[0] if results else None
        scanner_label = scanner_type
        if not host_result:
            host_info.notes = f"No response from {scanner_label}"

        # Process ports from port scanner
        if host_result:
            for port in host_result.ports:
                if port.state == "open":
                    host_info.open_ports.append(port.port)

                    service_name = self._guess_service(port.port)
                    service = ServiceInfo(
                        port=port.port,
                        protocol=port.protocol,
                        name=service_name,
                        version="",
                        product="",
                        banner=service_name,
                    )
                    host_info.services.append(service)

        # Ordinary TCP scan (connect + service detection)
        if verify_tcp:
            if self.nmap is None:
                self.nmap = NmapScanner()
            if host_info.open_ports:
                tcp_ports = ",".join(str(p) for p in sorted(set(host_info.open_ports)))
                print("[*] TCP connect scan (nmap) on open ports")
            else:
                tcp_ports = ports
                host_info.notes = (
                    host_info.notes + "; TCP connect scan fallback"
                    if host_info.notes
                    else "TCP connect scan fallback"
                )
                print("[*] TCP connect scan (nmap) on full port range")
            tcp_results = await self.nmap.scan_host_tcp_connect(
                target, ports=tcp_ports, version_detection=True, verbose=verbose
            )
            if tcp_results:
                tcp_host = tcp_results[0]
                # Replace services with detected ones
                host_info.services = []
                host_info.open_ports = []
                for port in tcp_host.ports:
                    if port.state != "open":
                        continue
                    host_info.services.append(
                        ServiceInfo(
                            port=port.port,
                            protocol=port.protocol,
                            name=port.service,
                            version=port.version,
                            product=port.product,
                            banner=f"{port.product} {port.version}".strip(),
                        )
                    )
                    host_info.open_ports.append(port.port)

        # UDP scan (optional)
        if include_udp:
            if self.nmap is None:
                self.nmap = NmapScanner()
            udp_ports = ports_udp or os.environ.get("CLAWPWN_MASSCAN_PORTS_UDP", "1-65535")
            print("[*] UDP scan (nmap)")
            udp_results = await self.nmap.scan_host_udp(target, ports=udp_ports, verbose=verbose)
            if udp_results:
                udp_host = udp_results[0]
                for port in udp_host.ports:
                    if port.state != "open":
                        continue
                    host_info.open_ports.append(port.port)
                    host_info.services.append(
                        ServiceInfo(
                            port=port.port,
                            protocol=port.protocol,
                            name=port.service or "udp",
                            version=port.version,
                            product=port.product,
                            banner=f"{port.product} {port.version}".strip(),
                        )
                    )

        host_info.open_ports = sorted(set(host_info.open_ports))

        # Log the discovery
        if self.session:
            self.session.add_log(
                f"Discovered host {target}: {len(host_info.open_ports)} open ports",
                phase="Reconnaissance",
            )

        print(f"[+] {target}: {len(host_info.open_ports)} open ports")
        return host_info

    def _rate_for_scan(self) -> int:
        rate = os.environ.get("CLAWPWN_MASSCAN_RATE", "10000")
        try:
            return int(rate)
        except ValueError:
            return 10000

    def _ports_for_scan(self, scan_type: str, full_scan: bool) -> str:
        if full_scan or scan_type == "full" or scan_type == "deep":
            default = "1-65535"
            env_key = "CLAWPWN_MASSCAN_PORTS_DEEP"
        elif scan_type == "quick":
            default = "1-1024"
            env_key = "CLAWPWN_MASSCAN_PORTS_QUICK"
        else:
            default = "1-10000"
            env_key = "CLAWPWN_MASSCAN_PORTS_NORMAL"
        return os.environ.get(env_key, default)

    def _guess_service(self, port: int) -> str:
        common = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "smb",
            3306: "mysql",
            5432: "postgres",
            6379: "redis",
            3389: "rdp",
            8080: "http",
            8443: "https",
        }
        return common.get(port, "unknown")

    async def enumerate_target(self, target: str) -> dict[str, Any]:
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

    def print_summary(self, results: dict[str, Any]) -> None:
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
                    print(f"  {service.port}/{service.protocol}: {service.name}{banner}")

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
