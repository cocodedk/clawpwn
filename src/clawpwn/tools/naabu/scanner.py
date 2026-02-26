"""Naabu port scanner implementation."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from clawpwn.tools.masscan import HostResult, PortScanResult

from .helpers import can_sudo_without_password, is_root, parse_float_env


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
        on_port: Callable[[str, int], None] | None = None,
    ) -> list[HostResult]:
        """Scan a target host. Calls on_port(ip, port) for each discovery if provided."""
        use_sudo = not is_root() and can_sudo_without_password(self.binary)
        cmd = ["sudo", self.binary] if use_sudo else [self.binary]
        cmd.extend(["-host", target, "-port", ports, "-rate", str(rate), "-json"])
        if not verbose:
            cmd.append("-silent")

        if verbose and not on_port:
            print(f"[verbose] Naabu command: {' '.join(cmd)}")

        effective_timeout = (
            timeout if timeout is not None else parse_float_env("CLAWPWN_NAABU_TIMEOUT")
        )
        started = time.perf_counter()

        if verbose:
            return await self._run_streaming(cmd, target, effective_timeout, started, on_port)
        return await self._run_buffered(cmd, target, effective_timeout, started, on_port)

    async def _run_buffered(
        self,
        cmd: list[str],
        target: str,
        timeout: float | None,
        started: float,
        on_port: Callable[[str, int], None] | None = None,
    ) -> list[HostResult]:
        """Run naabu with buffered I/O (silent mode)."""
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except TimeoutError:
            await self._kill(process, started, timeout)

        if process.returncode != 0:
            raise RuntimeError(f"Naabu scan failed: {(stderr or b'').decode() or 'Unknown error'}")

        if on_port:
            for line in stdout.decode().strip().splitlines():
                try:
                    entry = json.loads(line.strip())
                    ip = entry.get("ip") or entry.get("host")
                    port = entry.get("port")
                    if ip and isinstance(port, int):
                        on_port(ip, port)
                except json.JSONDecodeError:
                    pass

        results = self._parse_output(stdout.decode())
        return results if results else [HostResult(ip=target, ports=[])]

    async def _run_streaming(
        self,
        cmd: list[str],
        target: str,
        timeout: float | None,
        started: float,
        on_port: Callable[[str, int], None] | None = None,
    ) -> list[HostResult]:
        """Run naabu streaming stderr for live progress in verbose mode."""
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout_lines: list[str] = []

        async def _read_stderr():
            assert process.stderr is not None
            async for raw in process.stderr:
                if not on_port:
                    print(f"[naabu] {raw.decode().rstrip()}")

        async def _read_stdout():
            assert process.stdout is not None
            async for raw in process.stdout:
                line = raw.decode().rstrip()
                stdout_lines.append(line)
                try:
                    entry = json.loads(line)
                    port = entry.get("port", "?")
                    ip = entry.get("ip") or entry.get("host", "?")
                    if on_port and isinstance(port, int):
                        on_port(str(ip), port)
                    else:
                        print(f"[naabu] found {ip}:{port}")
                except json.JSONDecodeError:
                    pass

        try:
            await asyncio.wait_for(
                asyncio.gather(_read_stderr(), _read_stdout(), process.wait()),
                timeout=timeout,
            )
        except TimeoutError:
            await self._kill(process, started, timeout)
        elapsed = time.perf_counter() - started
        if not on_port:
            print(f"[verbose] Naabu exit code: {process.returncode} ({elapsed:.2f}s)")

        if process.returncode != 0:
            raise RuntimeError(f"Naabu scan failed (exit {process.returncode})")

        results = self._parse_output("\n".join(stdout_lines))
        return results if results else [HostResult(ip=target, ports=[])]

    @staticmethod
    async def _kill(process, started: float, timeout: float | None) -> None:
        """Terminate a timed-out process and raise."""
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except TimeoutError:
            process.kill()
            await process.wait()
        elapsed = time.perf_counter() - started
        raise RuntimeError(
            f"Naabu scan timed out after {elapsed:.1f}s (timeout={timeout})."
        ) from None

    @staticmethod
    def _parse_output(output: str) -> list[HostResult]:
        """Parse naabu JSONL output into HostResult objects grouped by IP."""
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
            if ip and isinstance(port, int) and 1 <= port <= 65535:
                hosts.setdefault(ip, []).append(port)
        return [
            HostResult(
                ip=ip,
                ports=[
                    PortScanResult(port=p, protocol="tcp", state="open") for p in sorted(set(pl))
                ],
            )
            for ip, pl in hosts.items()
        ]
