"""Nmap wrapper for network discovery."""

import asyncio
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any


def _is_root() -> bool:
    """Return True if running as root (Unix) or elevated admin (Windows)."""
    if sys.platform == "win32":
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False
    try:
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def _can_sudo_without_password(binary: str) -> bool:
    """Check if we can run a binary with sudo without password prompt."""
    bin_path = shutil.which(binary)
    if not bin_path:
        return False
    try:
        result = subprocess.run(
            ["sudo", "-n", bin_path, "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _needs_sudo(binary: str) -> bool:
    """Check if we need sudo to run privileged scans."""
    return not _is_root() and _can_sudo_without_password(binary)


@dataclass
class PortScanResult:
    """Represents a single port scan result."""

    port: int
    protocol: str
    state: str
    service: str
    version: str = ""
    product: str = ""
    extra_info: str = ""


@dataclass
class HostResult:
    """Represents a single host scan result."""

    ip: str
    hostname: str = ""
    status: str = ""
    ports: list[PortScanResult] = field(default_factory=list)
    os_info: dict[str, Any] = field(default_factory=dict)


class NmapScanner:
    """Wrapper for nmap subprocess calls."""

    def __init__(self):
        self._check_nmap()

    def _check_nmap(self) -> None:
        """Verify nmap is installed."""
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise RuntimeError("nmap is not installed. Please install nmap first.") from e

    async def scan_host(
        self,
        target: str,
        ports: str | None = None,
        aggressive: bool = False,
        version_detection: bool = True,
        os_detection: bool = False,
        script_scan: bool = False,
        tcp_connect: bool = False,
        udp: bool = False,
        verbose: bool = False,
    ) -> list[HostResult]:
        """
        Scan a target host.

        Args:
            target: IP address or hostname
            ports: Port range (e.g., "80,443" or "1-1000")
            aggressive: Use aggressive scan timing
            version_detection: Detect service versions
            os_detection: Attempt OS detection (requires root)
            script_scan: Run default NSE scripts
        """
        # Check if we need sudo for privileged scans
        needs_priv = udp or os_detection
        use_sudo = needs_priv and not _is_root() and _can_sudo_without_password("nmap")

        cmd = ["sudo", "nmap"] if use_sudo else ["nmap"]
        cmd.extend([target, "-oX", "-"])  # Output as XML to stdout

        if ports:
            cmd.extend(["-p", ports])

        if aggressive:
            cmd.append("-T4")
        else:
            cmd.append("-T2")

        if tcp_connect:
            cmd.extend(["-sT", "-Pn"])
        elif udp:
            cmd.extend(["-sU", "-Pn"])
        # Use unprivileged scan settings when not running as root and no sudo
        elif not _is_root() and not use_sudo:
            cmd.extend(["-sT", "-Pn", "--unprivileged"])

        if version_detection:
            cmd.append("-sV")

        if os_detection:
            cmd.append("-O")

        if script_scan:
            cmd.append("-sC")

        # Run nmap
        if verbose:
            print(f"[verbose] Nmap command: {' '.join(cmd)}")
        started = time.perf_counter()
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        if verbose:
            elapsed = time.perf_counter() - started
            print(f"[verbose] Nmap exit code: {process.returncode} ({elapsed:.2f}s)")

        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else "Unknown error"
            if verbose:
                error_msg = f"{error_msg}\nCommand: {' '.join(cmd)}"
            raise RuntimeError(f"Nmap scan failed: {error_msg}")

        # Parse XML output
        return self._parse_nmap_xml(stdout.decode())

    async def quick_scan(self, target: str, verbose: bool = False) -> list[HostResult]:
        """Quick scan of top 1000 ports."""
        return await self.scan_host(
            target, aggressive=True, version_detection=True, verbose=verbose
        )

    async def full_scan(self, target: str, verbose: bool = False) -> list[HostResult]:
        """Full scan of all ports with version detection."""
        return await self.scan_host(
            target,
            ports="1-65535",
            aggressive=True,
            version_detection=True,
            script_scan=True,
            verbose=verbose,
        )

    async def scan_host_tcp_connect(
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

    async def scan_host_udp(
        self, target: str, ports: str, verbose: bool = False
    ) -> list[HostResult]:
        """UDP scan for specific ports."""
        return await self.scan_host(
            target,
            ports=ports,
            aggressive=False,
            version_detection=False,
            udp=True,
            verbose=verbose,
        )

    async def ping_sweep(self, network: str) -> list[str]:
        """
        Perform a ping sweep to discover live hosts.

        Args:
            network: Network range (e.g., "192.168.1.0/24")
        """
        use_sudo = not _is_root() and _can_sudo_without_password("nmap")
        cmd = ["sudo", "nmap"] if use_sudo else ["nmap"]
        cmd.extend(["-sn", "-oX", "-", network])

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else "Unknown error"
            raise RuntimeError(f"Ping sweep failed: {error_msg}")

        hosts = self._parse_nmap_xml(stdout.decode())
        return [h.ip for h in hosts if h.status == "up"]

    def _parse_nmap_xml(self, xml_data: str) -> list[HostResult]:
        """Parse nmap XML output into HostResult objects."""
        try:
            import xml.etree.ElementTree as ET
        except ImportError:
            # Fallback if xml parsing fails
            return []

        results = []

        try:
            root = ET.fromstring(xml_data)

            for host in root.findall("host"):
                host_result = self._parse_host(host)
                if host_result:
                    results.append(host_result)
        except ET.ParseError:
            pass

        return results

    def _parse_host(self, host_elem) -> HostResult | None:
        """Parse a single host element from nmap XML."""

        # Get IP address
        address = host_elem.find("address[@addrtype='ipv4']")
        if address is None:
            address = host_elem.find("address")

        if address is None:
            return None

        ip = address.get("addr", "")

        # Get hostname
        hostnames = host_elem.find("hostnames")
        hostname = ""
        if hostnames is not None:
            hostname_elem = hostnames.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name", "")

        # Get status
        status_elem = host_elem.find("status")
        status = status_elem.get("state", "") if status_elem is not None else ""

        # Get ports
        ports = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                port_result = self._parse_port(port)
                if port_result:
                    ports.append(port_result)

        # Get OS info
        os_info = {}
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_info = {
                    "name": osmatch.get("name", ""),
                    "accuracy": osmatch.get("accuracy", ""),
                }

        return HostResult(
            ip=ip,
            hostname=hostname,
            status=status,
            ports=ports,
            os_info=os_info,
        )

    def _parse_port(self, port_elem) -> PortScanResult | None:
        """Parse a single port element from nmap XML."""
        portid = port_elem.get("portid", "")
        protocol = port_elem.get("protocol", "")

        # Get state
        state_elem = port_elem.find("state")
        state = state_elem.get("state", "") if state_elem is not None else ""

        # Get service info
        service = ""
        version = ""
        product = ""
        extra_info = ""

        service_elem = port_elem.find("service")
        if service_elem is not None:
            service = service_elem.get("name", "")
            version = service_elem.get("version", "")
            product = service_elem.get("product", "")
            extra_info = service_elem.get("extrainfo", "")

        try:
            port_num = int(portid)
        except ValueError:
            return None

        return PortScanResult(
            port=port_num,
            protocol=protocol,
            state=state,
            service=service,
            version=version,
            product=product,
            extra_info=extra_info,
        )


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
