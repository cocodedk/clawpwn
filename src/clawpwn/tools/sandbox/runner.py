"""Sandboxed script execution for custom attacks."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class ScriptResult:
    """Result of script execution."""

    exit_code: int
    stdout: str
    stderr: str
    script_path: str
    error: str | None = None


async def run_sandboxed_script(
    script: str,
    timeout: int = 30,
    project_dir: Path | None = None,
) -> ScriptResult:
    """Execute a Python script in a sandboxed subprocess.

    Args:
        script: Python script content to execute
        timeout: Maximum execution time in seconds
        project_dir: Project directory (for saving script to exploits/)

    Returns:
        ScriptResult with exit code, stdout, stderr, and script path
    """
    if project_dir is None:
        project_dir = Path.cwd()

    # Create exploits directory if it doesn't exist
    exploits_dir = project_dir / "exploits"
    exploits_dir.mkdir(exist_ok=True)

    # Save script with timestamp
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    script_path = exploits_dir / f"custom_script_{timestamp}.py"

    try:
        script_path.write_text(script)
    except Exception as e:
        return ScriptResult(
            exit_code=-1,
            stdout="",
            stderr="",
            script_path=str(script_path),
            error=f"Failed to write script: {e}",
        )

    # Execute script in subprocess
    try:
        process = await asyncio.create_subprocess_exec(
            "python3",
            str(script_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(project_dir),
        )

        # Wait for completion with timeout
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        exit_code = process.returncode or 0

        # Log execution to session if available
        _log_script_execution(project_dir, script_path, exit_code)

        return ScriptResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            script_path=str(script_path),
        )

    except TimeoutError:
        # Kill the process on timeout
        try:
            process.kill()
            await process.wait()
        except Exception:
            pass

        return ScriptResult(
            exit_code=-1,
            stdout="",
            stderr="",
            script_path=str(script_path),
            error=f"Script execution timed out after {timeout}s",
        )

    except Exception as e:
        return ScriptResult(
            exit_code=-1,
            stdout="",
            stderr="",
            script_path=str(script_path),
            error=f"Script execution failed: {e}",
        )


def _log_script_execution(project_dir: Path, script_path: Path, exit_code: int) -> None:
    """Log script execution to session for auditability."""
    try:
        from clawpwn.config import get_project_db_path
        from clawpwn.modules.session import SessionManager

        db_path = get_project_db_path(project_dir)
        if not db_path:
            return

        session = SessionManager(db_path)
        session.add_log(
            level="INFO",
            phase="exploit",
            message=f"Executed custom script: {script_path.name}",
            details={"script_path": str(script_path), "exit_code": exit_code},
        )
    except Exception:
        pass  # Don't fail if logging fails
