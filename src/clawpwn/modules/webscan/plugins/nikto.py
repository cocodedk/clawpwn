"""Nikto web scanner plugin."""

from collections.abc import Callable

from ..base import WebScannerPlugin
from ..models import WebScanConfig, WebScanFinding
from ..runtime import CommandResult, resolve_binary, run_command


def _severity_from_line(line: str) -> str:
    lowered = line.lower()
    if "cve-" in lowered or "vulnerab" in lowered:
        return "high"
    if "outdated" in lowered or "misconfig" in lowered:
        return "medium"
    return "low"


class NiktoWebScannerPlugin(WebScannerPlugin):
    """Run nikto and parse issue lines from output."""

    name = "nikto"

    def __init__(self, command_runner: Callable[..., object] | None = None):
        self._runner = command_runner or run_command

    async def scan(self, target: str, config: WebScanConfig) -> list[WebScanFinding]:
        binary = resolve_binary("nikto")
        if not binary:
            raise RuntimeError("nikto binary not found in PATH")

        command = [
            binary,
            "-host",
            target,
            "-ask",
            "no",
            "-nointeractive",
        ]
        if config.timeout is not None:
            command.extend(["-maxtime", str(max(30, int(config.timeout)))])
        result = await self._runner(
            command,
            timeout=None if config.timeout is None else max(60.0, config.timeout + 30.0),
            allowed_exit_codes=(0, 1),
            verbose=config.verbose,
        )
        assert isinstance(result, CommandResult)
        return self._parse_output(result.stdout, target)

    def _parse_output(self, output: str, target: str) -> list[WebScanFinding]:
        findings: list[WebScanFinding] = []
        ignored_prefixes = (
            "target ip",
            "target hostname",
            "target port",
            "start time",
            "end time",
            "server:",
            "host(s) tested",
        )
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line.startswith("+ "):
                continue
            content = line[2:].strip()
            if not content:
                continue
            lowered = content.lower()
            if any(lowered.startswith(prefix) for prefix in ignored_prefixes):
                continue

            title = content.split(":", 1)[0].strip()
            if not title:
                title = "Nikto finding"
            findings.append(
                WebScanFinding(
                    tool=self.name,
                    title=title,
                    severity=_severity_from_line(content),
                    description=content,
                    url=target,
                    attack_type="nikto",
                    evidence=content,
                    raw={"line": content},
                )
            )
        return findings
