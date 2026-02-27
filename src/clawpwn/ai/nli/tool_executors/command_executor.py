"""Executor for the run_command tool — shell command execution."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from clawpwn.utils.async_utils import safe_async_run


@dataclass
class CommandResult:
    """Result of a shell command execution."""

    exit_code: int
    stdout: str
    stderr: str
    script_path: str
    error: str | None = None


async def _run_shell_command(
    command: str,
    timeout: int,
    project_dir: Path,
) -> CommandResult:
    """Execute a shell command in a subprocess."""
    exploits_dir = project_dir / "exploits"
    exploits_dir.mkdir(exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    script_path = exploits_dir / f"command_{timestamp}.sh"

    try:
        script_path.write_text(f"#!/usr/bin/env bash\n{command}\n")
    except Exception as e:
        return CommandResult(-1, "", "", str(script_path), error=f"Failed to save command: {e}")

    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(project_dir),
        )

        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )

        return CommandResult(
            exit_code=process.returncode or 0,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            script_path=str(script_path),
        )

    except TimeoutError:
        try:
            process.kill()
            await process.wait()
        except Exception:
            pass
        return CommandResult(-1, "", "", str(script_path), error=f"Timed out after {timeout}s")

    except Exception as e:
        return CommandResult(-1, "", "", str(script_path), error=f"Execution failed: {e}")


def execute_run_command(params: dict[str, Any], project_dir: Path) -> str:
    """Execute a shell command and return results."""
    command = params.get("command", "")
    description = params.get("description", "Shell command")
    timeout = params.get("timeout", 30)
    user_approved = bool(params.get("user_approved", False))

    if not command:
        return "Error: command parameter is required."
    if not user_approved:
        return (
            "Approval required: command execution is blocked until the user explicitly "
            "approves it. Ask: 'Allow running this command? (yes/no)' and retry with "
            "user_approved=true only if the user says yes."
        )

    result = safe_async_run(_run_shell_command(command, timeout, project_dir))

    output = [f"Command execution: {description}\n$ {command}\n"]

    if result.exit_code == 0:
        output.append("Exit code: 0 (success)")
    else:
        output.append(f"Exit code: {result.exit_code}")

    output.append(f"Saved to: {result.script_path}")

    if result.stdout:
        output.append(f"\n--- STDOUT ---\n{result.stdout}")
    if result.stderr:
        output.append(f"\n--- STDERR ---\n{result.stderr}")
    if result.error:
        output.append(f"\nError: {result.error}")

    return "\n".join(output)
