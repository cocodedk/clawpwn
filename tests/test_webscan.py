"""Tests for modular web scan orchestration."""

from pathlib import Path

import pytest

from clawpwn.modules.scanner import ScanConfig, ScanResult
from clawpwn.modules.webscan import (
    BuiltinWebScannerPlugin,
    WebScanConfig,
    WebScanFinding,
    WebScannerPlugin,
    WebScanOrchestrator,
)


class FakePlugin(WebScannerPlugin):
    """Simple test plugin."""

    def __init__(self, name: str, findings: list[WebScanFinding]):
        self.name = name
        self._findings = findings

    async def scan(self, target: str, config: WebScanConfig) -> list[WebScanFinding]:
        return list(self._findings)


class FailingPlugin(WebScannerPlugin):
    """Plugin that always fails."""

    def __init__(self, name: str, message: str):
        self.name = name
        self._message = message

    async def scan(self, target: str, config: WebScanConfig) -> list[WebScanFinding]:
        raise RuntimeError(self._message)


class FakeBuiltinScanner:
    """Minimal scanner compatible with BuiltinWebScannerPlugin."""

    def __init__(self):
        self.calls: list[tuple[str, ScanConfig]] = []

    async def scan(self, target: str, config: ScanConfig) -> list[ScanResult]:
        self.calls.append((target, config))
        return [
            ScanResult(
                title="Missing Security Headers",
                severity="medium",
                description="Header check failed",
                url=target,
                attack_type="passive",
                evidence="none",
            )
        ]


@pytest.mark.asyncio
async def test_orchestrator_runs_selected_plugins() -> None:
    finding_a = WebScanFinding(
        tool="a",
        title="A",
        severity="low",
        description="a",
        url="https://example.com",
    )
    finding_b = WebScanFinding(
        tool="b",
        title="B",
        severity="high",
        description="b",
        url="https://example.com/login",
    )
    orchestrator = WebScanOrchestrator(
        plugins=[FakePlugin("a", [finding_a]), FakePlugin("b", [finding_b])]
    )

    findings = await orchestrator.scan_target(
        "https://example.com",
        config=WebScanConfig(depth="quick"),
        tools=["b"],
    )

    assert len(findings) == 1
    assert findings[0].tool == "b"
    assert findings[0].title == "B"


@pytest.mark.asyncio
async def test_orchestrator_deduplicates_findings() -> None:
    duplicate = WebScanFinding(
        tool="a",
        title="Duplicate",
        severity="medium",
        description="same",
        url="https://example.com",
    )
    orchestrator = WebScanOrchestrator(plugins=[FakePlugin("a", [duplicate, duplicate])])

    findings = await orchestrator.scan_target("https://example.com", config=WebScanConfig())

    assert len(findings) == 1


@pytest.mark.asyncio
async def test_orchestrator_rejects_unknown_tool() -> None:
    orchestrator = WebScanOrchestrator(plugins=[FakePlugin("a", [])])

    with pytest.raises(ValueError, match="Unknown web scanner tool"):
        await orchestrator.scan_target(
            "https://example.com",
            config=WebScanConfig(),
            tools=["missing"],
        )


@pytest.mark.asyncio
async def test_orchestrator_collects_plugin_errors_when_enabled() -> None:
    finding = WebScanFinding(
        tool="ok",
        title="Found",
        severity="low",
        description="ok",
        url="https://example.com",
    )
    orchestrator = WebScanOrchestrator(
        plugins=[
            FakePlugin("ok", [finding]),
            FailingPlugin("bad", "tool missing"),
        ]
    )

    findings, errors = await orchestrator.scan_target_with_diagnostics(
        "https://example.com",
        config=WebScanConfig(),
        tools=["ok", "bad"],
        continue_on_error=True,
    )

    assert len(findings) == 1
    assert findings[0].tool == "ok"
    assert len(errors) == 1
    assert errors[0].tool == "bad"
    assert "tool missing" in errors[0].message


@pytest.mark.asyncio
async def test_orchestrator_reports_progress_messages() -> None:
    finding = WebScanFinding(
        tool="ok",
        title="Found",
        severity="low",
        description="ok",
        url="https://example.com",
    )
    orchestrator = WebScanOrchestrator(
        plugins=[
            FakePlugin("ok", [finding]),
            FailingPlugin("bad", "boom"),
        ]
    )
    updates: list[str] = []

    await orchestrator.scan_target_with_diagnostics(
        "https://example.com",
        config=WebScanConfig(),
        tools=["ok", "bad"],
        continue_on_error=True,
        progress=updates.append,
    )

    assert any("[ok] started" in item for item in updates)
    assert any("[ok] completed" in item for item in updates)
    assert any("[bad] started" in item for item in updates)
    assert any("[bad] failed" in item for item in updates)


@pytest.mark.asyncio
async def test_builtin_plugin_adapts_scanner_results(project_dir: Path) -> None:
    fake = FakeBuiltinScanner()

    def factory(_: Path | None) -> FakeBuiltinScanner:
        return fake

    plugin = BuiltinWebScannerPlugin(project_dir=project_dir, scanner_factory=factory)
    findings = await plugin.scan("https://example.com", WebScanConfig(depth="deep"))

    assert len(findings) == 1
    assert findings[0].tool == "builtin"
    assert findings[0].title == "Missing Security Headers"
    assert fake.calls
    _, config = fake.calls[0]
    assert config.depth == "deep"
