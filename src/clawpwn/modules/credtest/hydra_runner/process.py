"""Hydra process execution helpers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path


@dataclass
class HydraExecutionResult:
    """Captured Hydra command execution output."""

    returncode: int | None
    stdout: str
    stderr: str
    file_output: str
    timed_out: bool = False

    @property
    def combined_output(self) -> str:
        return "\n".join(part for part in [self.stdout, self.stderr, self.file_output] if part)


async def run_hydra_command(
    command: list[str],
    output_path: Path,
    timeout: float = 180.0,
) -> HydraExecutionResult:
    """Run Hydra and collect stdout/stderr and output file content."""
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=3.0)
        except TimeoutError:
            process.kill()
            await process.wait()
        return HydraExecutionResult(
            returncode=None, stdout="", stderr="", file_output="", timed_out=True
        )

    return HydraExecutionResult(
        returncode=process.returncode,
        stdout=stdout_bytes.decode(errors="replace"),
        stderr=stderr_bytes.decode(errors="replace"),
        file_output=(
            output_path.read_text(encoding="utf-8", errors="ignore") if output_path.exists() else ""
        ),
    )
