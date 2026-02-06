"""Nuclei web scanner plugin."""

import json
from collections.abc import Callable

from ..base import WebScannerPlugin
from ..models import WebScanConfig, WebScanFinding
from ..runtime import CommandResult, resolve_binary, run_command


def _normalize_severity(value: str) -> str:
    normalized = value.strip().lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }
    return mapping.get(normalized, "info")


class NucleiWebScannerPlugin(WebScannerPlugin):
    """Run nuclei templates and parse JSONL findings."""

    name = "nuclei"

    def __init__(
        self,
        command_runner: Callable[..., object] | None = None,
    ):
        self._runner = command_runner or run_command

    async def scan(self, target: str, config: WebScanConfig) -> list[WebScanFinding]:
        binary = resolve_binary("nuclei")
        if not binary:
            raise RuntimeError("nuclei binary not found in PATH")

        command = [
            binary,
            "-u",
            target,
            "-jsonl",
            "-silent",
            "-timeout",
            str(max(5, int(config.timeout))),
        ]
        if config.depth == "quick":
            command.extend(["-severity", "critical,high"])
        elif config.depth == "normal":
            command.extend(["-severity", "critical,high,medium"])

        result = await self._runner(
            command,
            timeout=max(30.0, config.timeout + 10.0),
            verbose=config.verbose,
        )
        assert isinstance(result, CommandResult)
        return self._parse_findings(result.stdout, target)

    def _parse_findings(self, output: str, target: str) -> list[WebScanFinding]:
        findings: list[WebScanFinding] = []
        for line in output.splitlines():
            entry = line.strip()
            if not entry:
                continue
            try:
                obj = json.loads(entry)
            except json.JSONDecodeError:
                continue

            info = obj.get("info", {}) if isinstance(obj, dict) else {}
            template_id = str(obj.get("template-id", "")).strip()
            title = str(info.get("name") or template_id or "Nuclei finding").strip()
            severity = _normalize_severity(str(info.get("severity", "info")))
            description = str(info.get("description") or "").strip()
            if not description:
                description = f"Nuclei template {template_id or 'unknown'} matched."
            matched = str(obj.get("matched-at") or obj.get("host") or target).strip()
            evidence = str(obj.get("matcher-name") or "").strip()
            if not evidence:
                extracted = obj.get("extracted-results")
                if isinstance(extracted, list) and extracted:
                    evidence = ", ".join(str(item) for item in extracted[:3])

            findings.append(
                WebScanFinding(
                    tool=self.name,
                    title=title,
                    severity=severity,
                    description=description,
                    url=matched,
                    attack_type=f"nuclei:{template_id}" if template_id else "nuclei",
                    evidence=evidence,
                    raw=obj if isinstance(obj, dict) else {},
                )
            )
        return findings
