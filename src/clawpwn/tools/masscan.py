"""Masscan wrapper for fast network discovery."""

import asyncio
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class PortScanResult:
    """Represents a single port scan result."""

    port: int
    protocol: str
    state: str
    service: str = ""


@dataclass
class HostResult:
    """Represents a single host scan result."""

    ip: str
    ports: List[PortScanResult] = field(default_factory=list)


class MasscanScanner:
    """Wrapper for masscan subprocess calls."""

    def __init__(self):
        self._check_masscan()

    def _check_masscan(self) -> None:
        """Verify masscan is installed."""
        try:
            subprocess.run(["masscan", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("masscan is not installed. Please install masscan first.")

    async def scan_host(
        self,
        target: str,
        ports: str,
        rate: int = 10000,
        interface: Optional[str] = None,
        verbose: bool = False,
    ) -> List[HostResult]:
        """
        Scan a target host with masscan.

        Args:
            target: IP address or hostname
            ports: Port range (e.g., "80,443" or "1-1000")
            rate: Packets per second
            interface: Network interface (optional)
        """
        cmd = [
            "masscan",
            target,
            "-p",
            ports,
            "--rate",
            str(rate),
            "-oJ",
            "-",
        ]

        if interface:
            cmd.extend(["-e", interface])

        if verbose:
            print(f"[verbose] Masscan command: {' '.join(cmd)}")

        started = time.perf_counter()
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()
        elapsed = time.perf_counter() - started

        if verbose:
            print(f"[verbose] Masscan exit code: {process.returncode} ({elapsed:.2f}s)")

        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else "Unknown error"
            raise RuntimeError(f"Masscan scan failed: {error_msg}")

        return self._parse_masscan_json(stdout.decode())

    @staticmethod
    def _parse_masscan_json(output: str) -> List[HostResult]:
        """Parse masscan JSON output into HostResult objects."""
        data = output.strip()
        if not data:
            return []

        # Masscan sometimes emits trailing commas or extra whitespace
        cleaned = data.replace("\n", "").replace("\t", "").strip()
        if not cleaned.startswith("["):
            cleaned = f"[{cleaned}]"

        # Remove trailing commas before closing brackets
        cleaned = cleaned.replace(",]", "]").replace(",}", "}")

        try:
            items = json.loads(cleaned)
        except json.JSONDecodeError:
            return []

        hosts: Dict[str, HostResult] = {}

        for item in items:
            ip = item.get("ip")
            if not ip:
                continue
            host = hosts.setdefault(ip, HostResult(ip=ip))
            for port_entry in item.get("ports", []):
                port = port_entry.get("port")
                proto = port_entry.get("proto", "tcp")
                status = port_entry.get("status", "open")
                if port is None:
                    continue
                host.ports.append(
                    PortScanResult(
                        port=int(port),
                        protocol=str(proto),
                        state=str(status),
                    )
                )

        return list(hosts.values())
