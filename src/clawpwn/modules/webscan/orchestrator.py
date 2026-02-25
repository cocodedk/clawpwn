"""Coordinator for running one or more web scanner plugins."""

import time
from collections.abc import Callable, Iterable, Sequence

from .base import WebScannerPlugin
from .models import WebScanConfig, WebScanError, WebScanFinding


class WebScanOrchestrator:
    """Run selected web scanner plugins and normalize their outputs."""

    def __init__(self, plugins: Iterable[WebScannerPlugin] | None = None):
        self._plugins: dict[str, WebScannerPlugin] = {}
        for plugin in plugins or []:
            self.register(plugin)

    def register(self, plugin: WebScannerPlugin) -> None:
        """Register or replace a plugin by name."""
        self._plugins[plugin.name] = plugin

    def available_tools(self) -> list[str]:
        """Return sorted plugin names."""
        return sorted(self._plugins.keys())

    async def scan_target(
        self,
        target: str,
        config: WebScanConfig,
        tools: Sequence[str] | None = None,
    ) -> list[WebScanFinding]:
        """Run selected plugins for a target and return deduplicated findings."""
        findings, errors = await self.scan_target_with_diagnostics(
            target=target,
            config=config,
            tools=tools,
            continue_on_error=False,
        )
        if errors:
            first = errors[0]
            raise RuntimeError(f"{first.tool} scan failed: {first.message}")
        return findings

    async def scan_target_with_diagnostics(
        self,
        target: str,
        config: WebScanConfig,
        tools: Sequence[str] | None = None,
        continue_on_error: bool = True,
        progress: Callable[[str], None] | None = None,
    ) -> tuple[list[WebScanFinding], list[WebScanError]]:
        """Run selected plugins for a target and return findings plus tool errors."""
        selected = self._select_plugins(tools)
        findings: list[WebScanFinding] = []
        errors: list[WebScanError] = []
        for plugin in selected:
            started = time.perf_counter()
            if progress:
                progress(f"● [{plugin.name}] started")
            try:
                tool_findings = await plugin.scan(target, config)
                findings.extend(tool_findings)
                if progress:
                    elapsed = time.perf_counter() - started
                    progress(
                        f"✓ [{plugin.name}] completed: {len(tool_findings)} findings ({elapsed:.1f}s)"
                    )
            except Exception as exc:
                if progress:
                    elapsed = time.perf_counter() - started
                    progress(f"! [{plugin.name}] failed after {elapsed:.1f}s: {exc}")
                if not continue_on_error:
                    raise
                errors.append(WebScanError(tool=plugin.name, message=str(exc)))
        return self._dedupe(findings), errors

    def _select_plugins(self, tools: Sequence[str] | None) -> list[WebScannerPlugin]:
        if not self._plugins:
            return []

        if not tools:
            return [self._plugins[name] for name in self.available_tools()]

        missing = sorted({tool for tool in tools if tool not in self._plugins})
        if missing:
            available = ", ".join(self.available_tools()) or "none"
            raise ValueError(
                f"Unknown web scanner tool(s): {', '.join(missing)}. Available tools: {available}"
            )

        return [self._plugins[tool] for tool in tools]

    def _dedupe(self, findings: list[WebScanFinding]) -> list[WebScanFinding]:
        seen: set[tuple[str, str, str, str, str]] = set()
        deduped: list[WebScanFinding] = []
        for finding in findings:
            key = (
                finding.tool,
                finding.url,
                finding.title,
                finding.severity,
                finding.attack_type,
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped
