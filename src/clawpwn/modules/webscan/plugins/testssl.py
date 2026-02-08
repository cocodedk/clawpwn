"""testssl.sh TLS/SSL auditing plugin."""

import json
import tempfile
from collections.abc import Callable
from pathlib import Path

from ..base import WebScannerPlugin
from ..models import WebScanConfig, WebScanFinding
from ..runtime import resolve_binary, run_command

_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "WARN": "low",
    "INFO": "info",
    "OK": "info",
}


def _map_severity(value: str) -> str:
    return _SEVERITY_MAP.get(value.strip().upper(), "info")


def _is_reportable(severity: str) -> bool:
    """Filter out purely informational OK/INFO entries for brevity."""
    return severity in ("critical", "high", "medium", "low")


class TestSSLWebScannerPlugin(WebScannerPlugin):
    """Run testssl.sh and parse JSON findings for TLS/SSL issues."""

    name = "testssl"

    def __init__(self, command_runner: Callable[..., object] | None = None):
        self._runner = command_runner or run_command

    async def scan(self, target: str, config: WebScanConfig) -> list[WebScanFinding]:
        binary = resolve_binary("testssl.sh") or resolve_binary("testssl")
        if not binary:
            raise RuntimeError("testssl.sh binary not found in PATH")

        with tempfile.TemporaryDirectory(prefix="clawpwn-testssl-") as tmpdir:
            out_file = Path(tmpdir) / "results.json"
            command = self._build_command(binary, target, config, out_file)
            await self._runner(
                command,
                timeout=None if config.timeout is None else max(180.0, config.timeout * 4),
                allowed_exit_codes=(0, 1, 2),
                verbose=config.verbose,
            )
            return self._parse_output(out_file, target)

    def _build_command(
        self, binary: str, target: str, config: WebScanConfig, out_file: Path
    ) -> list[str]:
        command = [
            binary,
            "--jsonfile",
            str(out_file),
            "--severity",
            "LOW",
            "--sneaky",
        ]
        if config.depth == "quick":
            command.append("--fast")
        # 'deep' runs without --fast for full checks
        command.append(target)
        return command

    def _parse_output(self, out_file: Path, target: str) -> list[WebScanFinding]:
        if not out_file.exists():
            return []
        try:
            data = json.loads(out_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

        entries = data if isinstance(data, list) else []
        findings: list[WebScanFinding] = []

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            test_id = str(entry.get("id") or "").strip()
            raw_severity = str(entry.get("severity") or "INFO").strip()
            severity = _map_severity(raw_severity)

            if not _is_reportable(severity):
                continue

            finding_text = str(entry.get("finding") or "").strip()
            ip = str(entry.get("ip") or "").strip()
            port = str(entry.get("port") or "").strip()

            title = test_id or "TLS/SSL issue"
            description = finding_text or f"testssl.sh check '{test_id}' flagged an issue."
            evidence = finding_text
            if ip and port:
                evidence = f"{ip}:{port} — {evidence}"

            findings.append(
                WebScanFinding(
                    tool=self.name,
                    title=title,
                    severity=severity,
                    description=description,
                    url=target,
                    attack_type="tls",
                    evidence=evidence,
                    raw=entry,
                )
            )

        return findings
