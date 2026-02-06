"""WPScan WordPress security scanner plugin."""

import json
from collections.abc import Callable

from ..base import WebScannerPlugin
from ..models import WebScanConfig, WebScanFinding
from ..runtime import CommandResult, resolve_binary, run_command


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _extract_cvss(vuln: dict) -> float | None:
    """Extract a CVSS score from a wpscan vulnerability object."""
    cvss = vuln.get("cvss")
    if isinstance(cvss, dict):
        score = cvss.get("score")
        if isinstance(score, (int, float)):
            return float(score)
    return None


class WPScanWebScannerPlugin(WebScannerPlugin):
    """Run wpscan and parse JSON output for WordPress vulnerabilities."""

    name = "wpscan"

    def __init__(self, command_runner: Callable[..., object] | None = None):
        self._runner = command_runner or run_command

    async def scan(self, target: str, config: WebScanConfig) -> list[WebScanFinding]:
        binary = resolve_binary("wpscan")
        if not binary:
            raise RuntimeError("wpscan binary not found in PATH")

        command = self._build_command(binary, target, config)
        result = await self._runner(
            command,
            timeout=max(120.0, config.timeout * 3),
            allowed_exit_codes=(0, 1, 2, 3, 4, 5),
            verbose=config.verbose,
        )
        assert isinstance(result, CommandResult)
        return self._parse_output(result.stdout, target)

    def _build_command(self, binary: str, target: str, config: WebScanConfig) -> list[str]:
        command = [
            binary,
            "--url",
            target,
            "--format",
            "json",
            "--no-banner",
            "--random-user-agent",
        ]
        if config.depth == "quick":
            command.extend(["--enumerate", "vp"])
        elif config.depth == "deep":
            command.extend(
                [
                    "--enumerate",
                    "vp,vt,u,ap,at,tt,cb,dbe",
                    "--plugins-detection",
                    "aggressive",
                ]
            )
        else:
            command.extend(["--enumerate", "vp,vt,u"])
        return command

    def _parse_output(self, stdout: str, target: str) -> list[WebScanFinding]:
        """Parse wpscan JSON output into normalised findings."""
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, dict):
            return []

        findings: list[WebScanFinding] = []

        # Top-level vulnerabilities (WordPress core)
        for vuln in _iter_vulns(data, "main_theme"):
            findings.append(self._vuln_to_finding(vuln, target, "theme"))
        for vuln in _iter_vulns(data, "version"):
            findings.append(self._vuln_to_finding(vuln, target, "core"))

        # Plugin vulnerabilities
        plugins = data.get("plugins")
        if isinstance(plugins, dict):
            for _slug, plugin_data in plugins.items():
                if not isinstance(plugin_data, dict):
                    continue
                for vuln in plugin_data.get("vulnerabilities", []):
                    if isinstance(vuln, dict):
                        findings.append(self._vuln_to_finding(vuln, target, "plugin"))

        # Theme vulnerabilities
        themes = data.get("themes")
        if isinstance(themes, dict):
            for _slug, theme_data in themes.items():
                if not isinstance(theme_data, dict):
                    continue
                for vuln in theme_data.get("vulnerabilities", []):
                    if isinstance(vuln, dict):
                        findings.append(self._vuln_to_finding(vuln, target, "theme"))

        # Interesting findings (e.g. exposed readme, uploads dir)
        for item in data.get("interesting_findings", []):
            if isinstance(item, dict):
                findings.append(self._interesting_to_finding(item, target))

        return findings

    def _vuln_to_finding(self, vuln: dict, target: str, source: str) -> WebScanFinding:
        title = str(vuln.get("title") or "WordPress vulnerability").strip()
        cvss = _extract_cvss(vuln)
        severity = _severity_from_cvss(cvss)
        refs = vuln.get("references", {})
        urls = refs.get("url", []) if isinstance(refs, dict) else []
        evidence = ", ".join(str(u) for u in urls[:3]) if isinstance(urls, list) else ""
        return WebScanFinding(
            tool=self.name,
            title=title,
            severity=severity,
            description=f"WPScan detected a {source} vulnerability: {title}",
            url=target,
            attack_type="wordpress",
            evidence=evidence,
            raw=vuln,
        )

    def _interesting_to_finding(self, item: dict, target: str) -> WebScanFinding:
        url = str(item.get("url") or target).strip()
        entry_type = str(item.get("type") or "").strip()
        desc = str(item.get("to_s") or entry_type or "Interesting finding").strip()
        return WebScanFinding(
            tool=self.name,
            title=f"WordPress: {desc[:80]}",
            severity="info",
            description=desc,
            url=url,
            attack_type="wordpress",
            evidence=entry_type,
            raw=item,
        )


def _iter_vulns(data: dict, key: str):
    """Yield vulnerability dicts from a top-level wpscan key."""
    section = data.get(key)
    if not isinstance(section, dict):
        return
    for vuln in section.get("vulnerabilities", []):
        if isinstance(vuln, dict):
            yield vuln
