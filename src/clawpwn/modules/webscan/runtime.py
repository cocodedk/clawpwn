"""Runtime helpers for invoking external web scanning tools."""

import asyncio
import shlex
import shutil
import time
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass
class CommandResult:
    """Captured subprocess result."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str


def resolve_binary(name: str) -> str | None:
    """Return absolute path for a binary name when available."""
    return shutil.which(name)


async def run_command(
    command: list[str],
    timeout: float | None = None,
    allowed_exit_codes: Iterable[int] = (0,),
    verbose: bool = False,
) -> CommandResult:
    """Run a subprocess command and capture decoded output."""
    started = time.perf_counter()
    if verbose:
        cmd_preview = " ".join(shlex.quote(part) for part in command)
        print(f"[webscan] running: {cmd_preview}")
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        if timeout is None:
            stdout, stderr = await process.communicate()
        else:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=3.0)
        except TimeoutError:
            process.kill()
            await process.wait()
        cmd_preview = " ".join(command)
        raise RuntimeError(f"Command timed out: {cmd_preview}") from None

    result = CommandResult(
        command=list(command),
        returncode=process.returncode,
        stdout=stdout.decode(errors="replace"),
        stderr=stderr.decode(errors="replace"),
    )
    elapsed = time.perf_counter() - started

    allowed = set(allowed_exit_codes)
    if result.returncode not in allowed:
        snippet = (result.stderr or result.stdout).strip().splitlines()
        detail = snippet[0] if snippet else "unknown error"
        raise RuntimeError(f"Command failed with exit code {result.returncode}: {detail}")
    if verbose:
        print(f"[webscan] done ({elapsed:.2f}s): exit={result.returncode}")
    return result
