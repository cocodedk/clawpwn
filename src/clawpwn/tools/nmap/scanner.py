"""Nmap scanner class and core functionality."""

import asyncio
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

from .privileges import _can_sudo_without_password, _is_root


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
        from .xml_parser import parse_nmap_xml

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
        return parse_nmap_xml(stdout.decode())

    async def ping_sweep(self, network: str) -> list[str]:
        """
        Perform a ping sweep to discover live hosts.

        Args:
            network: Network range (e.g., "192.168.1.0/24")
        """
        from .xml_parser import parse_nmap_xml

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

        hosts = parse_nmap_xml(stdout.decode())
        return [h.ip for h in hosts if h.status == "up"]

    def _parse_nmap_xml(self, xml_data: str) -> list[HostResult]:
        """Parse nmap XML output (delegates to xml_parser module)."""
        from .xml_parser import parse_nmap_xml

        return parse_nmap_xml(xml_data)
