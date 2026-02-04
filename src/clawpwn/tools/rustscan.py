"""RustScan wrapper for fast port discovery."""

import asyncio
import re
import shutil
import time

from clawpwn.tools.masscan import HostResult, PortScanResult


class RustScanScanner:
    """Wrapper for rustscan subprocess calls."""

    def __init__(self):
        self.binary = self._check_rustscan()

    def _check_rustscan(self) -> str:
        """Verify rustscan is installed."""
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
        # -q/--quiet: output only ports, do not run nmap
        # -p: port range, -b: batch size, -T: timeout ms
        cmd = [
            self.binary,
            "-p",
            ports,
            "-b",
            str(batch_size),
            "-T",
            str(timeout_ms),
            "-q",
            target,
        ]

        if verbose:
            print(f"[verbose] RustScan command: {' '.join(cmd)}")

        started = time.perf_counter()
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()
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
