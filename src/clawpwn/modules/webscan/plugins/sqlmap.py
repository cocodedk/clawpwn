"""Sqlmap SQL injection scanner plugin."""

import tempfile
from collections.abc import Callable

from ..base import WebScannerPlugin
from ..models import WebScanConfig, WebScanFinding
from ..runtime import CommandResult, resolve_binary, run_command

# Injection type -> severity mapping
_INJECTION_SEVERITY: dict[str, str] = {
    "union": "critical",
    "stacked": "critical",
    "error": "high",
    "boolean": "high",
    "time": "high",
    "inline": "medium",
}


def _severity_for_technique(technique: str) -> str:
    lowered = technique.lower()
    for key, sev in _INJECTION_SEVERITY.items():
        if key in lowered:
            return sev
    return "high"


class SqlmapWebScannerPlugin(WebScannerPlugin):
    """Run sqlmap in batch mode and parse injection findings."""

    name = "sqlmap"

    def __init__(self, command_runner: Callable[..., object] | None = None):
        self._runner = command_runner or run_command

    async def scan(self, target: str, config: WebScanConfig) -> list[WebScanFinding]:
        binary = resolve_binary("sqlmap")
        if not binary:
            raise RuntimeError("sqlmap binary not found in PATH")

        with tempfile.TemporaryDirectory(prefix="clawpwn-sqlmap-") as tmpdir:
            command = self._build_command(binary, target, config, tmpdir)
            result = await self._runner(
                command,
                timeout=max(120.0, config.timeout * 3),
                allowed_exit_codes=(0, 1),
                verbose=config.verbose,
            )
            assert isinstance(result, CommandResult)
            return self._parse_output(result.stdout, result.stderr, target)

    def _build_command(
        self, binary: str, target: str, config: WebScanConfig, tmpdir: str
    ) -> list[str]:
        command = [
            binary,
            "-u",
            target,
            "--batch",
            "--output-dir",
            tmpdir,
            "--forms",
            "--crawl=1",
        ]
        if config.depth == "quick":
            command.extend(["--level=1", "--risk=1"])
        elif config.depth == "deep":
            command.extend(["--level=5", "--risk=3", "--technique=BEUSTQ"])
        else:
            command.extend(["--level=3", "--risk=2"])
        return command

    def _parse_output(self, stdout: str, stderr: str, target: str) -> list[WebScanFinding]:
        """Parse sqlmap stdout/stderr for injection point summaries."""
        findings: list[WebScanFinding] = []
        combined = stdout + "\n" + stderr
        current_param: str | None = None

        for raw_line in combined.splitlines():
            line = raw_line.strip()

            # Detect parameter header: "Parameter: id (GET)"
            if line.startswith("Parameter:"):
                current_param = line.replace("Parameter:", "").strip()
                continue

            # Detect injection type line: "Type: boolean-based blind"
            if line.startswith("Type:") and current_param:
                technique = line.replace("Type:", "").strip()
                title_text = technique or "SQL Injection"
                findings.append(
                    WebScanFinding(
                        tool=self.name,
                        title=f"SQL Injection ({title_text}): {current_param}",
                        severity=_severity_for_technique(technique),
                        description=(
                            f"sqlmap detected {technique} SQL injection "
                            f"on parameter '{current_param}'."
                        ),
                        url=target,
                        attack_type="SQL Injection",
                        evidence=f"Parameter: {current_param}, Type: {technique}",
                        raw={"parameter": current_param, "type": technique},
                    )
                )

        return findings
