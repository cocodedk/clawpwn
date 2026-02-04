"""Masscan wrapper for fast network discovery."""

import asyncio
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field


def _parse_float_env(name: str, default: float | None = 3600.0) -> float | None:
    """Parse optional float from environment; return default if unset or invalid."""
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    try:
        return float(val)
    except ValueError:
        return default


def _is_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def _can_sudo_without_password(binary_path: str) -> bool:
    """Check if we can run a binary with sudo without password prompt."""
    if not binary_path or not os.path.isfile(binary_path):
        return False
    try:
        result = subprocess.run(
            ["sudo", "-n", binary_path, "--help"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


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
    ports: list[PortScanResult] = field(default_factory=list)


class MasscanScanner:
    """Wrapper for masscan subprocess calls."""

    def __init__(self):
        self.binary = self._check_masscan()

    def _check_masscan(self) -> str:
        """Verify masscan is installed."""
        path = shutil.which("masscan")
        if not path:
            raise RuntimeError("masscan is not installed. Please install masscan first.")
        return path

    async def scan_host(
        self,
        target: str,
        ports: str,
        rate: int = 10000,
        interface: str | None = None,
        sudo: bool = False,
        verbose: bool = False,
        timeout: float | None = None,
    ) -> list[HostResult]:
        """
        Scan a target host with masscan.

        Args:
            target: IP address or hostname
            ports: Port range (e.g., "80,443" or "1-1000")
            rate: Packets per second
            interface: Network interface (optional)
            sudo: Use sudo (auto-detected if not specified)
        """
        # Auto-detect if we need and can use sudo
        use_sudo = sudo or (not _is_root() and _can_sudo_without_password(self.binary))

        cmd = ["sudo", self.binary] if use_sudo else [self.binary]
        cmd.extend(
            [
                target,
                "--ports",
                ports,
                "--rate",
                str(rate),
                "-oJ",
                "-",
            ]
        )

        if interface:
            cmd.extend(["-e", interface])

        if verbose:
            print(f"[verbose] Masscan command: {' '.join(cmd)}")

        effective_timeout = (
            timeout if timeout is not None else _parse_float_env("CLAWPWN_MASSCAN_TIMEOUT")
        )
        started = time.perf_counter()
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=effective_timeout
            )
        except TimeoutError:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except TimeoutError:
                process.kill()
                await process.wait()
            if process.stdout:
                stdout = await process.stdout.read()
            else:
                stdout = b""
            if process.stderr:
                stderr = await process.stderr.read()
            else:
                stderr = b""
            elapsed = time.perf_counter() - started
            raise RuntimeError(
                f"Masscan scan timed out after {elapsed:.1f}s (timeout={effective_timeout})."
            ) from None
        elapsed = time.perf_counter() - started

        if verbose:
            print(f"[verbose] Masscan exit code: {process.returncode} ({elapsed:.2f}s)")

        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else "Unknown error"
            raise RuntimeError(f"Masscan scan failed: {error_msg}")

        stdout_text = stdout.decode()
        stderr_text = stderr.decode() if stderr else ""
        results = self._parse_masscan_json(stdout_text)

        if verbose and stderr_text:
            print(f"[verbose] Masscan stderr: {stderr_text.strip()}")

        if not results and stderr_text:
            lowered = stderr_text.lower()
            keywords = [
                "error",
                "failed",
                "permission",
                "denied",
                "cannot",
                "could not",
                "exiting",
            ]
            if any(k in lowered for k in keywords):
                raise RuntimeError(f"Masscan scan failed: {stderr_text.strip()}")

        return results

    @staticmethod
    def _parse_masscan_json(output: str) -> list[HostResult]:
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

        hosts: dict[str, HostResult] = {}

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
