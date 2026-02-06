"""Tests for sqlmap, wpscan, and testssl.sh plugins and NLI wiring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawpwn.ai.nli.constants import VULN_CATEGORIES, VULN_CATEGORY_ALIASES
from clawpwn.ai.nli.tool_executors import EXTERNAL_TOOLS
from clawpwn.ai.nli.tools import WEB_SCAN_TOOL
from clawpwn.modules.webscan import WebScanConfig
from clawpwn.modules.webscan.plugins.sqlmap import SqlmapWebScannerPlugin
from clawpwn.modules.webscan.plugins.testssl import TestSSLWebScannerPlugin
from clawpwn.modules.webscan.plugins.wpscan import WPScanWebScannerPlugin
from clawpwn.modules.webscan.runtime import CommandResult

# ---------------------------------------------------------------------------
# sqlmap plugin
# ---------------------------------------------------------------------------


class TestSqlmapPlugin:
    """Tests for SqlmapWebScannerPlugin."""

    @pytest.mark.asyncio
    async def test_binary_not_found_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("clawpwn.modules.webscan.plugins.sqlmap.resolve_binary", lambda _: None)
        plugin = SqlmapWebScannerPlugin()
        with pytest.raises(RuntimeError, match="sqlmap binary not found"):
            await plugin.scan("http://target/page?id=1", WebScanConfig())

    @pytest.mark.asyncio
    async def test_parses_injection_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stdout = (
            "[INFO] testing 'AND boolean-based blind'\n"
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "    Title: AND boolean-based blind\n"
            "    Type: time-based blind\n"
            "    Title: MySQL >= 5.0 time-based blind\n"
        )

        async def fake_runner(*_args, **_kwargs):
            return CommandResult(command=["sqlmap"], returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.sqlmap.resolve_binary", lambda _: "/bin/sqlmap"
        )
        plugin = SqlmapWebScannerPlugin(command_runner=fake_runner)
        findings = await plugin.scan("http://target/page?id=1", WebScanConfig(depth="deep"))

        assert len(findings) == 2
        assert all(f.attack_type == "SQL Injection" for f in findings)
        assert any("boolean" in f.title.lower() for f in findings)
        assert any("time" in f.title.lower() for f in findings)

    @pytest.mark.asyncio
    async def test_depth_flags(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: list[list[str]] = []

        async def capture_runner(command, **_kwargs):
            captured.append(list(command))
            return CommandResult(command=command, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.sqlmap.resolve_binary", lambda _: "/bin/sqlmap"
        )
        plugin = SqlmapWebScannerPlugin(command_runner=capture_runner)

        await plugin.scan("http://t", WebScanConfig(depth="quick"))
        assert "--level=1" in captured[-1]

        await plugin.scan("http://t", WebScanConfig(depth="deep"))
        assert "--level=5" in captured[-1]
        assert "--risk=3" in captured[-1]


# ---------------------------------------------------------------------------
# wpscan plugin
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# testssl plugin
# ---------------------------------------------------------------------------


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
            # Write the JSON output file
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
            # Write empty JSON array so parser doesn't fail
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


# ---------------------------------------------------------------------------
# NLI wiring
# ---------------------------------------------------------------------------


class TestNLIWiring:
    """Verify new tools are properly wired into NLI schemas and constants."""

    def test_vuln_categories_tls_exists(self) -> None:
        assert "tls" in VULN_CATEGORIES
        assert "testssl" in VULN_CATEGORIES["tls"]["tools"]

    def test_vuln_categories_wordpress_exists(self) -> None:
        assert "wordpress" in VULN_CATEGORIES
        assert "wpscan" in VULN_CATEGORIES["wordpress"]["tools"]

    def test_sqli_category_includes_sqlmap(self) -> None:
        assert "sqlmap" in VULN_CATEGORIES["sqli"]["tools"]

    def test_aliases_tls(self) -> None:
        for alias in ("ssl", "tls", "certificate", "tls/ssl"):
            assert VULN_CATEGORY_ALIASES.get(alias) == "tls", f"Alias '{alias}' not mapped to tls"

    def test_aliases_wordpress(self) -> None:
        for alias in ("wordpress", "wp", "wpscan"):
            assert VULN_CATEGORY_ALIASES.get(alias) == "wordpress", (
                f"Alias '{alias}' not mapped to wordpress"
            )

    def test_external_tools_registry(self) -> None:
        for tool in ("sqlmap", "wpscan", "testssl"):
            assert tool in EXTERNAL_TOOLS, f"{tool} not in EXTERNAL_TOOLS"
            assert "binary" in EXTERNAL_TOOLS[tool]
            assert "install" in EXTERNAL_TOOLS[tool]

    def test_web_scan_tool_enum_includes_new_tools(self) -> None:
        tools_enum = WEB_SCAN_TOOL["input_schema"]["properties"]["tools"]["items"]["enum"]
        for tool in ("sqlmap", "wpscan", "testssl"):
            assert tool in tools_enum, f"{tool} not in WEB_SCAN_TOOL tools enum"

    def test_vuln_categories_enum_includes_new_categories(self) -> None:
        cats_enum = WEB_SCAN_TOOL["input_schema"]["properties"]["vuln_categories"]["items"]["enum"]
        for cat in ("tls", "wordpress"):
            assert cat in cats_enum, f"{cat} not in WEB_SCAN_TOOL vuln_categories enum"

    def test_factory_includes_new_plugins(self) -> None:
        from clawpwn.modules.webscan.factory import create_default_webscan_plugins

        plugins = create_default_webscan_plugins(None, scanner_factory=lambda _: None)
        names = {p.name for p in plugins}
        for name in ("sqlmap", "wpscan", "testssl"):
            assert name in names, f"{name} not in factory plugins"
