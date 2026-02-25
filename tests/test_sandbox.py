"""Tests for sandboxed script execution module."""

from pathlib import Path

import pytest

from clawpwn.tools.sandbox import ScriptResult, run_sandboxed_script


class TestSandboxedScripts:
    """Test sandboxed script execution."""

    @pytest.mark.asyncio
    async def test_simple_script_execution(self, project_dir: Path):
        """Test successful execution of a simple script."""
        script = """
print("Hello from script")
print("Line 2")
"""

        result = await run_sandboxed_script(script, timeout=5, project_dir=project_dir)

        assert result.exit_code == 0
        assert "Hello from script" in result.stdout
        assert "Line 2" in result.stdout
        assert result.error is None

    @pytest.mark.asyncio
    async def test_script_with_exit_code(self, project_dir: Path):
        """Test script that exits with non-zero code."""
        script = """
import sys
print("Error message")
sys.exit(1)
"""

        result = await run_sandboxed_script(script, timeout=5, project_dir=project_dir)

        assert result.exit_code == 1
        assert "Error message" in result.stdout

    @pytest.mark.asyncio
    async def test_script_timeout(self, project_dir: Path):
        """Test script execution timeout."""
        script = """
import time
time.sleep(10)
print("This should not print")
"""

        result = await run_sandboxed_script(script, timeout=1, project_dir=project_dir)

        assert result.exit_code == -1
        assert "timed out" in result.error.lower()

    @pytest.mark.asyncio
    async def test_script_with_stderr(self, project_dir: Path):
        """Test script that writes to stderr."""
        script = """
import sys
print("stdout message")
print("stderr message", file=sys.stderr)
"""

        result = await run_sandboxed_script(script, timeout=5, project_dir=project_dir)

        assert result.exit_code == 0
        assert "stdout message" in result.stdout
        assert "stderr message" in result.stderr

    @pytest.mark.asyncio
    async def test_script_saved_to_exploits(self, project_dir: Path):
        """Test that script is saved to exploits directory."""
        script = """print("test")"""

        result = await run_sandboxed_script(script, timeout=5, project_dir=project_dir)

        script_path = Path(result.script_path)
        assert script_path.exists()
        assert script_path.parent == project_dir / "exploits"
        assert script_path.name.startswith("custom_script_")
        assert script_path.suffix == ".py"

    @pytest.mark.asyncio
    async def test_script_with_imports(self, project_dir: Path):
        """Test script that uses standard library imports."""
        script = """
import json
import os

data = {"test": "value"}
print(json.dumps(data))
print(f"Python PID: {os.getpid()}")
"""

        result = await run_sandboxed_script(script, timeout=5, project_dir=project_dir)

        assert result.exit_code == 0
        assert "test" in result.stdout
        assert "Python PID:" in result.stdout

    @pytest.mark.asyncio
    async def test_script_syntax_error(self, project_dir: Path):
        """Test script with syntax errors."""
        script = """
print("unclosed string
"""

        result = await run_sandboxed_script(script, timeout=5, project_dir=project_dir)

        assert result.exit_code != 0
        assert len(result.stderr) > 0

    @pytest.mark.asyncio
    async def test_script_runtime_error(self, project_dir: Path):
        """Test script that raises runtime error."""
        script = """
x = 1 / 0
"""

        result = await run_sandboxed_script(script, timeout=5, project_dir=project_dir)

        assert result.exit_code != 0
        assert "ZeroDivisionError" in result.stderr or "division" in result.stderr.lower()

    def test_script_result_dataclass(self):
        """Test ScriptResult dataclass."""
        result = ScriptResult(
            exit_code=0,
            stdout="output",
            stderr="",
            script_path="/tmp/script.py",
        )

        assert result.exit_code == 0
        assert result.stdout == "output"
        assert result.error is None
