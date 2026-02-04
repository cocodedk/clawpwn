"""RustScan wrapper for fast port discovery."""

import asyncio
import os
import re
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


class RustScanScanner:
    """Wrapper for rustscan subprocess calls."""

    def __init__(self):
        self.binary = self._check_rustscan()

    def _check_rustscan(self) -> str:
        """Verify rustscan is installed, preferring cargo-installed binary."""
        # Prefer cargo-installed rustscan (can have setcap, snap cannot)
        cargo_path = Path.home() / ".cargo" / "bin" / "rustscan"
        if cargo_path.is_file() and os.access(cargo_path, os.X_OK):
            return str(cargo_path)
        path = shutil.which("rustscan")
        if not path:
            raise RuntimeError("rustscan is not installed. Please install rustscan first.")
        return path

    async def scan_host(
        self,
        target: str,
        ports: str = "1-65535",
        batch_size: int = 5000,
        timeout_ms: int = 1000,
        verbose: bool = False,
        timeout: float | None = None,
    ) -> list[HostResult]:
        """
        Scan a target host with rustscan.

        Args:
            target: IP address or hostname
            ports: Port range (e.g., "80,443" or "1-1000")
            batch_size: Ports per batch (lower = slower, less aggressive)
            timeout_ms: Timeout per port in milliseconds
            verbose: Print verbose output
        """
        # Check if we need sudo
        use_sudo = not _is_root() and _can_sudo_without_password(self.binary)

        # -r: port range (e.g., 1-1000), -p: comma-separated ports (e.g., 80,443)
        # -b: batch size, -t: timeout ms, -g: greppable output
        cmd = ["sudo", self.binary] if use_sudo else [self.binary]
        cmd.extend(
            [
                "-b",
                str(batch_size),
                "-t",
                str(timeout_ms),
                "-g",  # greppable output (ports only)
                "-a",
                target,
            ]
        )

        # Use -r for ranges (contains dash, no comma), -p for comma-separated
        if "-" in ports and "," not in ports:
            cmd.extend(["-r", ports])
        else:
            cmd.extend(["-p", ports])

        if verbose:
            print(f"[verbose] RustScan command: {' '.join(cmd)}")

        effective_timeout = timeout if timeout is not None else _parse_float_env("RUSTSCAN_TIMEOUT")
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
            stdout = b""
            stderr = b""
            elapsed = time.perf_counter() - started
            raise RuntimeError(
                f"RustScan scan timed out after {elapsed:.1f}s (timeout={effective_timeout})."
            ) from None
        elapsed = time.perf_counter() - started

        if verbose:
            print(f"[verbose] RustScan exit code: {process.returncode} ({elapsed:.2f}s)")

        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else "Unknown error"
            raise RuntimeError(f"RustScan scan failed: {error_msg}")

        stdout_text = stdout.decode()
        stderr_text = stderr.decode() if stderr else ""
        results = self._parse_output(target, stdout_text)

        if verbose and stderr_text:
            print(f"[verbose] RustScan stderr: {stderr_text.strip()}")

        return results

    @staticmethod
    def _parse_output(target: str, output: str) -> list[HostResult]:
        """Parse rustscan quiet output into HostResult objects.

        RustScan --quiet outputs discovered ports, typically one per line
        or comma-separated (e.g. "22\n80\n443" or "22,80,443").
        """
        if not output or not output.strip():
            return [HostResult(ip=target, ports=[])]

        # Collect all port numbers: digits only, one per line or comma-separated
        port_numbers: list[int] = []
        for part in re.split(r"[\s,]+", output.strip()):
            part = part.strip()
            if not part:
                continue
            # Handle "22/tcp" style if present
            if "/" in part:
                part = part.split("/")[0]
            if part.isdigit():
                p = int(part)
                if 1 <= p <= 65535 and p not in port_numbers:
                    port_numbers.append(p)

        port_results = [
            PortScanResult(port=p, protocol="tcp", state="open") for p in sorted(port_numbers)
        ]
        return [HostResult(ip=target, ports=port_results)]
