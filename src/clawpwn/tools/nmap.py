"""Nmap wrapper for network discovery."""

import asyncio
import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any


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
    ports: List[PortScanResult] = field(default_factory=list)
    os_info: Dict[str, Any] = field(default_factory=dict)


class NmapScanner:
    """Wrapper for nmap subprocess calls."""

    def __init__(self):
        self._check_nmap()

    def _check_nmap(self) -> None:
        """Verify nmap is installed."""
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("nmap is not installed. Please install nmap first.")

    async def scan_host(
        self,
        target: str,
        ports: Optional[str] = None,
        aggressive: bool = False,
        version_detection: bool = True,
        os_detection: bool = False,
        script_scan: bool = False,
    ) -> List[HostResult]:
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
        cmd = ["nmap", target, "-oX", "-"]  # Output as XML to stdout

        if ports:
            cmd.extend(["-p", ports])

        if aggressive:
            cmd.append("-T4")
        else:
            cmd.append("-T2")

        # Use unprivileged scan settings when not running as root
        if os.geteuid() != 0:
            cmd.extend(["-sT", "-Pn", "--unprivileged"])

        if version_detection:
            cmd.append("-sV")

        if os_detection:
            cmd.append("-O")

        if script_scan:
            cmd.append("-sC")

        # Run nmap
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else "Unknown error"
            raise RuntimeError(f"Nmap scan failed: {error_msg}")

        # Parse XML output
        return self._parse_nmap_xml(stdout.decode())

    async def quick_scan(self, target: str) -> List[HostResult]:
        """Quick scan of top 1000 ports."""
        return await self.scan_host(target, aggressive=True, version_detection=True)

    async def full_scan(self, target: str) -> List[HostResult]:
        """Full scan of all ports with version detection."""
        return await self.scan_host(
            target,
            ports="1-65535",
            aggressive=True,
            version_detection=True,
            script_scan=True,
        )

    async def ping_sweep(self, network: str) -> List[str]:
        """
        Perform a ping sweep to discover live hosts.

        Args:
            network: Network range (e.g., "192.168.1.0/24")
        """
        cmd = ["nmap", "-sn", "-oX", "-", network]

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

    def _parse_nmap_xml(self, xml_data: str) -> List[HostResult]:
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

    def _parse_host(self, host_elem) -> Optional[HostResult]:
        """Parse a single host element from nmap XML."""
        import xml.etree.ElementTree as ET

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

    def _parse_port(self, port_elem) -> Optional[PortScanResult]:
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
