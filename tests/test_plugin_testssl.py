"""Tests for the testssl.sh web scanner plugin."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawpwn.modules.webscan import WebScanConfig
from clawpwn.modules.webscan.plugins.testssl import TestSSLWebScannerPlugin
from clawpwn.modules.webscan.runtime import CommandResult


class TestTestSSLPlugin:
    """Tests for TestSSLWebScannerPlugin."""

    @pytest.mark.asyncio
    async def test_binary_not_found_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.testssl.resolve_binary", lambda _: None
        )
        plugin = TestSSLWebScannerPlugin()
        with pytest.raises(RuntimeError, match="testssl.sh binary not found"):
            await plugin.scan("https://example.com", WebScanConfig())

    @pytest.mark.asyncio
    async def test_parses_json_findings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        entries = [
            {
                "id": "heartbleed",
                "severity": "HIGH",
                "finding": "VULNERABLE (CVE-2014-0160)",
                "ip": "1.2.3.4",
                "port": "443",
            },
            {
                "id": "cbc_tls1",
                "severity": "MEDIUM",
                "finding": "CBC ciphers offered",
                "ip": "1.2.3.4",
                "port": "443",
            },
            {
                "id": "overall_grade",
                "severity": "OK",
                "finding": "Grade: A",
                "ip": "1.2.3.4",
                "port": "443",
            },
        ]

        async def fake_runner(command, **_kwargs):
            for i, part in enumerate(command):
                if part == "--jsonfile" and i + 1 < len(command):
                    Path(command[i + 1]).write_text(json.dumps(entries), encoding="utf-8")
            return CommandResult(command=command, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.testssl.resolve_binary",
            lambda name: "/bin/testssl.sh" if name == "testssl.sh" else None,
        )
        plugin = TestSSLWebScannerPlugin(command_runner=fake_runner)
        findings = await plugin.scan("https://example.com:443", WebScanConfig())

        # OK severity is filtered out
        assert len(findings) == 2
        assert findings[0].title == "heartbleed"
        assert findings[0].severity == "high"
        assert findings[0].attack_type == "tls"
        assert findings[1].severity == "medium"

    @pytest.mark.asyncio
    async def test_quick_depth_adds_fast_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[list[str]] = []

        async def capture_runner(command, **_kwargs):
            captured.append(list(command))
            for i, part in enumerate(command):
                if part == "--jsonfile" and i + 1 < len(command):
                    Path(command[i + 1]).write_text("[]", encoding="utf-8")
            return CommandResult(command=command, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.testssl.resolve_binary",
            lambda name: "/bin/testssl.sh" if name == "testssl.sh" else None,
        )
        plugin = TestSSLWebScannerPlugin(command_runner=capture_runner)

        await plugin.scan("https://t", WebScanConfig(depth="quick"))
        assert "--fast" in captured[-1]

        await plugin.scan("https://t", WebScanConfig(depth="deep"))
        assert "--fast" not in captured[-1]
