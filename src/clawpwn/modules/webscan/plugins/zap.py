"""OWASP ZAP baseline scanner plugin."""

import json
import tempfile
from collections.abc import Callable
from pathlib import Path

from ..base import WebScannerPlugin
from ..models import WebScanConfig, WebScanFinding
from ..runtime import resolve_binary, run_command


def _severity_from_risk(risk_code: str) -> str:
    mapping = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    return mapping.get(str(risk_code).strip(), "info")


class ZAPWebScannerPlugin(WebScannerPlugin):
    """Run ZAP baseline and parse JSON alert output."""

    name = "zap"

    def __init__(self, command_runner: Callable[..., object] | None = None):
        self._runner = command_runner or run_command

    async def scan(self, target: str, config: WebScanConfig) -> list[WebScanFinding]:
        with tempfile.TemporaryDirectory(prefix="clawpwn-zap-") as tmpdir:
            out_file = Path(tmpdir) / "zap_report.json"
            command = self._build_command(target=target, out_file=out_file, depth=config.depth)
            result = await self._runner(
                command,
                timeout=None if config.timeout is None else max(90.0, config.timeout + 60.0),
                allowed_exit_codes=(0, 1, 2),
                verbose=config.verbose,
            )
            if not out_file.exists():
                stderr = getattr(result, "stderr", "")
                raise RuntimeError(f"ZAP did not produce a JSON report: {stderr[:200]}")
            return self._parse_output(out_file)

    def _build_command(self, target: str, out_file: Path, depth: str) -> list[str]:
        minutes = {"quick": 1, "normal": 2}.get(depth, 5)

        zap_baseline = resolve_binary("zap-baseline.py")
        if zap_baseline:
            return [
                zap_baseline,
                "-t",
                target,
                "-J",
                str(out_file),
                "-m",
                str(minutes),
            ]

        docker = resolve_binary("docker")
        if docker:
            mount_dir = str(out_file.parent)
            return [
                docker,
                "run",
                "--rm",
                "-v",
                f"{mount_dir}:/zap/wrk",
                "ghcr.io/zaproxy/zaproxy:stable",
                "zap-baseline.py",
                "-t",
                target,
                "-J",
                f"/zap/wrk/{out_file.name}",
                "-m",
                str(minutes),
            ]

        raise RuntimeError("neither zap-baseline.py nor docker is available")

    def _parse_output(self, out_file: Path) -> list[WebScanFinding]:
        data = json.loads(out_file.read_text(encoding="utf-8"))
        sites = data.get("site", []) if isinstance(data, dict) else []
        if not isinstance(sites, list):
            return []

        findings: list[WebScanFinding] = []
        for site in sites:
            if not isinstance(site, dict):
                continue
            alerts = site.get("alerts", [])
            if not isinstance(alerts, list):
                continue
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                name = str(alert.get("name") or "ZAP alert").strip()
                severity = _severity_from_risk(str(alert.get("riskcode", "0")))
                desc = str(alert.get("desc") or "").strip() or "ZAP baseline alert."
                instances = alert.get("instances", [])
                instance = instances[0] if isinstance(instances, list) and instances else {}
                url = str(instance.get("uri") or site.get("@name") or "").strip()
                if not url:
                    url = str(site.get("@name") or "")
                evidence = str(instance.get("evidence") or instance.get("method") or "").strip()
                findings.append(
                    WebScanFinding(
                        tool=self.name,
                        title=name,
                        severity=severity,
                        description=desc,
                        url=url,
                        attack_type="zap",
                        evidence=evidence,
                        raw=alert,
                    )
                )
        return findings
