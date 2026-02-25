"""Naabu port scanner implementation."""

import asyncio
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from clawpwn.tools.masscan import HostResult, PortScanResult


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


class NaabuScanner:
    """Wrapper for naabu subprocess calls."""

    def __init__(self):
        self.binary = self._check_naabu()

    def _check_naabu(self) -> str:
        """Verify naabu is installed, checking common Go binary locations."""
        for candidate in [
            Path.home() / ".local" / "bin" / "naabu",
            Path.home() / "go" / "bin" / "naabu",
        ]:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        path = shutil.which("naabu")
        if not path:
            raise RuntimeError("naabu is not installed. Please install naabu first.")
        return path

    async def scan_host(
        self,
        target: str,
        ports: str = "1-65535",
        rate: int = 1000,
        verbose: bool = False,
        timeout: float | None = None,
    ) -> list[HostResult]:
        """Scan a target host with naabu.

        Args:
            target: IP address or hostname
            ports: Port range (e.g., "80,443" or "1-1000")
            rate: Packets per second
            verbose: Print verbose output
            timeout: Overall scan timeout in seconds
        """
        use_sudo = not _is_root() and _can_sudo_without_password(self.binary)

        cmd = ["sudo", self.binary] if use_sudo else [self.binary]
        cmd.extend(
            [
                "-host",
                target,
                "-port",
                ports,
                "-rate",
                str(rate),
                "-json",
                "-silent",
            ]
        )

        if verbose:
            print(f"[verbose] Naabu command: {' '.join(cmd)}")

        effective_timeout = (
            timeout if timeout is not None else _parse_float_env("CLAWPWN_NAABU_TIMEOUT")
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
            elapsed = time.perf_counter() - started
            raise RuntimeError(
                f"Naabu scan timed out after {elapsed:.1f}s (timeout={effective_timeout})."
            ) from None
        elapsed = time.perf_counter() - started

        if verbose:
            print(f"[verbose] Naabu exit code: {process.returncode} ({elapsed:.2f}s)")

        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else "Unknown error"
            raise RuntimeError(f"Naabu scan failed: {error_msg}")

        stdout_text = stdout.decode()
        stderr_text = stderr.decode() if stderr else ""
        results = self._parse_output(stdout_text)

        if verbose and stderr_text:
            print(f"[verbose] Naabu stderr: {stderr_text.strip()}")

        return results if results else [HostResult(ip=target, ports=[])]

    @staticmethod
    def _parse_output(output: str) -> list[HostResult]:
        """Parse naabu JSONL output into HostResult objects.

        Each line is a JSON object like: {"ip":"10.0.0.1","port":80}
        Results are grouped by IP address.
        """
        if not output or not output.strip():
            return []

        hosts: dict[str, list[int]] = {}
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = entry.get("ip") or entry.get("host")
            port = entry.get("port")
            if not ip or not isinstance(port, int):
                continue
            if 1 <= port <= 65535:
                hosts.setdefault(ip, []).append(port)

        return [
            HostResult(
                ip=ip,
                ports=[
                    PortScanResult(port=p, protocol="tcp", state="open")
                    for p in sorted(set(port_list))
                ],
            )
            for ip, port_list in hosts.items()
        ]
