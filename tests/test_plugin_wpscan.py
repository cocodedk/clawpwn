"""Tests for the wpscan web scanner plugin."""

from __future__ import annotations

import json

import pytest

from clawpwn.modules.webscan import WebScanConfig
from clawpwn.modules.webscan.plugins.wpscan import WPScanWebScannerPlugin
from clawpwn.modules.webscan.runtime import CommandResult


class TestWPScanPlugin:
    """Tests for WPScanWebScannerPlugin."""

    @pytest.mark.asyncio
    async def test_binary_not_found_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("clawpwn.modules.webscan.plugins.wpscan.resolve_binary", lambda _: None)
        plugin = WPScanWebScannerPlugin()
        with pytest.raises(RuntimeError, match="wpscan binary not found"):
            await plugin.scan("http://wp-site.com", WebScanConfig())

    @pytest.mark.asyncio
    async def test_parses_json_vulnerabilities(self, monkeypatch: pytest.MonkeyPatch) -> None:
        wpscan_json = json.dumps(
            {
                "version": {
                    "number": "5.9",
                    "vulnerabilities": [
                        {
                            "title": "WP Core SQLi in REST API",
                            "cvss": {"score": 9.8},
                            "references": {"url": ["https://wpscan.com/vuln/1"]},
                        }
                    ],
                },
                "plugins": {
                    "contact-form-7": {
                        "vulnerabilities": [
                            {
                                "title": "CF7 XSS via upload",
                                "cvss": {"score": 6.1},
                                "references": {},
                            }
                        ]
                    }
                },
                "interesting_findings": [
                    {
                        "url": "http://wp-site.com/readme.html",
                        "type": "readme",
                        "to_s": "WordPress readme found",
                    }
                ],
            }
        )

        async def fake_runner(*_args, **_kwargs):
            return CommandResult(command=["wpscan"], returncode=0, stdout=wpscan_json, stderr="")

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.wpscan.resolve_binary", lambda _: "/bin/wpscan"
        )
        plugin = WPScanWebScannerPlugin(command_runner=fake_runner)
        findings = await plugin.scan("http://wp-site.com", WebScanConfig())

        assert len(findings) == 3
        # Core vuln: CVSS 9.8 -> critical
        core = [f for f in findings if "Core" in f.title]
        assert core and core[0].severity == "critical"
        # Plugin vuln: CVSS 6.1 -> medium
        plugin_f = [f for f in findings if "CF7" in f.title]
        assert plugin_f and plugin_f[0].severity == "medium"
        # Interesting finding: info
        info = [f for f in findings if "readme" in f.title.lower()]
        assert info and info[0].severity == "info"

    @pytest.mark.asyncio
    async def test_depth_enumerate_flags(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[list[str]] = []

        async def capture_runner(command, **_kwargs):
            captured.append(list(command))
            return CommandResult(command=command, returncode=0, stdout="{}", stderr="")

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.wpscan.resolve_binary", lambda _: "/bin/wpscan"
        )
        plugin = WPScanWebScannerPlugin(command_runner=capture_runner)

        await plugin.scan("http://t", WebScanConfig(depth="quick"))
        assert "vp" in captured[-1]

        await plugin.scan("http://t", WebScanConfig(depth="deep"))
        assert "--plugins-detection" in captured[-1]
        assert "aggressive" in captured[-1]
