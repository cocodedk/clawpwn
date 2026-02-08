"""Tests for sqlmap, wpscan, and testssl.sh plugins and NLI wiring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawpwn.ai.nli.constants import VULN_CATEGORIES, VULN_CATEGORY_ALIASES
from clawpwn.ai.nli.tool_executors import EXTERNAL_TOOLS
from clawpwn.ai.nli.tools import WEB_SCAN_TOOL
from clawpwn.modules.webscan import WebScanConfig
from clawpwn.modules.webscan.plugins.sqlmap import SqlmapWebScannerPlugin, _SqlmapRequestContext
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

    @pytest.mark.asyncio
    async def test_stateful_second_pass_uses_cookie_data_and_csrf(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: list[list[str]] = []
        first = CommandResult(command=["sqlmap"], returncode=0, stdout="", stderr="")
        second = CommandResult(
            command=["sqlmap"],
            returncode=0,
            stdout="Parameter: username (POST)\nType: boolean-based blind\n",
            stderr="",
        )
        responses = [first, second]

        async def fake_runner(command, **_kwargs):
            captured.append(list(command))
            return responses.pop(0)

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.sqlmap.resolve_binary", lambda _: "/bin/sqlmap"
        )
        plugin = SqlmapWebScannerPlugin(command_runner=fake_runner)

        async def fake_context(_target: str) -> _SqlmapRequestContext:
            return _SqlmapRequestContext(
                action_url="http://target/phpMyAdmin/index.php",
                cookie_header="PHPSESSID=abc123",
                post_data="pma_username=test&pma_password=test&token=abc",
                csrf_token="token",
            )

        monkeypatch.setattr(plugin, "_derive_request_context", fake_context)
        findings = await plugin.scan("http://target/phpMyAdmin/", WebScanConfig(depth="deep"))

        assert len(captured) == 2
        second_command = captured[1]
        assert "--cookie" in second_command
        assert "PHPSESSID=abc123" in second_command
        assert "--data" in second_command
        assert "pma_username=test&pma_password=test&token=abc" in second_command
        assert "--csrf-token" in second_command
        assert "token" in second_command
        assert findings

    @pytest.mark.asyncio
    async def test_timeout_triggers_stateful_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: list[list[str]] = []
        second = CommandResult(
            command=["sqlmap"],
            returncode=0,
            stdout="Parameter: username (POST)\nType: boolean-based blind\n",
            stderr="",
        )
        calls = 0

        async def fake_runner(command, **_kwargs):
            nonlocal calls
            calls += 1
            captured.append(list(command))
            if calls == 1:
                raise RuntimeError("Command timed out: sqlmap")
            return second

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.sqlmap.resolve_binary", lambda _: "/bin/sqlmap"
        )
        plugin = SqlmapWebScannerPlugin(command_runner=fake_runner)

        async def fake_context(_target: str) -> _SqlmapRequestContext:
            return _SqlmapRequestContext(
                action_url="http://target/phpMyAdmin/index.php",
                cookie_header="PHPSESSID=abc123",
                post_data="pma_username=test&pma_password=test&token=abc",
                csrf_token="token",
            )

        monkeypatch.setattr(plugin, "_derive_request_context", fake_context)
        findings = await plugin.scan("http://target/phpMyAdmin/", WebScanConfig(depth="deep"))

        assert len(captured) == 2
        assert "--forms" in captured[0]
        assert "--data" in captured[1]
        assert findings

    @pytest.mark.asyncio
    async def test_returns_feedback_finding_when_only_hints_present(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stdout = "#1045 - Access denied for user 'admin'@'localhost' (using password: NO)"

        async def fake_runner(*_args, **_kwargs):
            return CommandResult(command=["sqlmap"], returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.sqlmap.resolve_binary", lambda _: "/bin/sqlmap"
        )
        plugin = SqlmapWebScannerPlugin(command_runner=fake_runner)
        findings = await plugin.scan("http://target/phpMyAdmin/", WebScanConfig(depth="quick"))

        assert len(findings) == 1
        assert findings[0].attack_type == "Attack Feedback"
        assert "hint" in findings[0].evidence.lower()

    @pytest.mark.asyncio
    async def test_returns_feedback_finding_when_block_signals_present(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stdout = "HTTP 429 Too many requests. Request blocked by WAF."

        async def fake_runner(*_args, **_kwargs):
            return CommandResult(command=["sqlmap"], returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.sqlmap.resolve_binary", lambda _: "/bin/sqlmap"
        )
        plugin = SqlmapWebScannerPlugin(command_runner=fake_runner)
        findings = await plugin.scan("http://target/phpMyAdmin/", WebScanConfig(depth="quick"))

        assert len(findings) == 1
        assert findings[0].attack_type == "Attack Feedback"
        assert findings[0].raw.get("feedback_policy") in {"backoff", "stop_and_replan"}

    @pytest.mark.asyncio
    async def test_injection_findings_include_feedback_metadata(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stdout = (
            "Parameter: id (GET)\n"
            "Type: boolean-based blind\n"
            "#1045 - Access denied for user 'admin'@'localhost' (using password: NO)\n"
        )

        async def fake_runner(*_args, **_kwargs):
            return CommandResult(command=["sqlmap"], returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.sqlmap.resolve_binary", lambda _: "/bin/sqlmap"
        )
        plugin = SqlmapWebScannerPlugin(command_runner=fake_runner)
        findings = await plugin.scan("http://target/page?id=1", WebScanConfig(depth="quick"))

        assert findings
        assert "feedback_policy" in findings[0].raw


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
        for tool in ("sqlmap", "wpscan", "testssl", "searchsploit"):
            assert tool in EXTERNAL_TOOLS, f"{tool} not in EXTERNAL_TOOLS"
            assert "binary" in EXTERNAL_TOOLS[tool]
            assert "install" in EXTERNAL_TOOLS[tool]

    def test_web_scan_tool_enum_includes_new_tools(self) -> None:
        tools_enum = WEB_SCAN_TOOL["input_schema"]["properties"]["tools"]["items"]["enum"]
        for tool in ("sqlmap", "wpscan", "testssl", "searchsploit"):
            assert tool in tools_enum, f"{tool} not in WEB_SCAN_TOOL tools enum"

    def test_vuln_categories_enum_includes_new_categories(self) -> None:
        cats_enum = WEB_SCAN_TOOL["input_schema"]["properties"]["vuln_categories"]["items"]["enum"]
        for cat in ("tls", "wordpress"):
            assert cat in cats_enum, f"{cat} not in WEB_SCAN_TOOL vuln_categories enum"

    def test_factory_includes_new_plugins(self) -> None:
        from clawpwn.modules.webscan.factory import create_default_webscan_plugins

        plugins = create_default_webscan_plugins(None, scanner_factory=lambda _: None)
        names = {p.name for p in plugins}
        for name in ("sqlmap", "wpscan", "testssl", "searchsploit"):
            assert name in names, f"{name} not in factory plugins"


# ---------------------------------------------------------------------------
# Timeout handling
# ---------------------------------------------------------------------------


class TestTimeoutDefaults:
    """Verify that timeout defaults to None (no timeout) across models and plugins."""

    def test_webscan_config_default_timeout_is_none(self) -> None:
        config = WebScanConfig()
        assert config.timeout is None

    def test_webscan_config_explicit_timeout(self) -> None:
        config = WebScanConfig(timeout=120.0)
        assert config.timeout == 120.0

    def test_scan_config_default_timeout_is_none(self) -> None:
        from clawpwn.modules.scanner.models import ScanConfig

        config = ScanConfig(target="http://t")
        assert config.timeout is None

    def test_web_scan_tool_schema_no_default_timeout(self) -> None:
        """The web_scan tool schema describes timeout as no-default."""
        from clawpwn.ai.nli.tools import WEB_SCAN_TOOL

        desc = WEB_SCAN_TOOL["input_schema"]["properties"]["timeout"]["description"]
        assert "no default" in desc.lower()
        assert "run to completion" in desc.lower()


class TestPluginNoneTimeout:
    """Verify that plugins pass timeout=None to run_command when config.timeout is None."""

    @pytest.mark.asyncio
    async def test_nuclei_none_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from clawpwn.modules.webscan.plugins.nuclei import NucleiWebScannerPlugin

        captured_kwargs: list[dict] = []

        async def capture_runner(command, **kwargs):
            captured_kwargs.append(kwargs)
            return CommandResult(command=command, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.nuclei.resolve_binary", lambda _: "/bin/nuclei"
        )
        plugin = NucleiWebScannerPlugin(command_runner=capture_runner)
        await plugin.scan("http://t", WebScanConfig())

        assert captured_kwargs[0]["timeout"] is None

    @pytest.mark.asyncio
    async def test_nuclei_explicit_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from clawpwn.modules.webscan.plugins.nuclei import NucleiWebScannerPlugin

        captured_kwargs: list[dict] = []

        async def capture_runner(command, **kwargs):
            captured_kwargs.append(kwargs)
            return CommandResult(command=command, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.nuclei.resolve_binary", lambda _: "/bin/nuclei"
        )
        plugin = NucleiWebScannerPlugin(command_runner=capture_runner)
        await plugin.scan("http://t", WebScanConfig(timeout=60.0))

        assert captured_kwargs[0]["timeout"] == max(30.0, 60.0 + 10.0)

    @pytest.mark.asyncio
    async def test_nuclei_no_cli_timeout_when_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from clawpwn.modules.webscan.plugins.nuclei import NucleiWebScannerPlugin

        captured_commands: list[list[str]] = []

        async def capture_runner(command, **_kwargs):
            captured_commands.append(list(command))
            return CommandResult(command=command, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.nuclei.resolve_binary", lambda _: "/bin/nuclei"
        )
        plugin = NucleiWebScannerPlugin(command_runner=capture_runner)
        await plugin.scan("http://t", WebScanConfig())

        assert "-timeout" not in captured_commands[0]

    @pytest.mark.asyncio
    async def test_nikto_none_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from clawpwn.modules.webscan.plugins.nikto import NiktoWebScannerPlugin

        captured_kwargs: list[dict] = []
        captured_commands: list[list[str]] = []

        async def capture_runner(command, **kwargs):
            captured_kwargs.append(kwargs)
            captured_commands.append(list(command))
            return CommandResult(command=command, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.nikto.resolve_binary", lambda _: "/bin/nikto"
        )
        plugin = NiktoWebScannerPlugin(command_runner=capture_runner)
        await plugin.scan("http://t", WebScanConfig())

        assert captured_kwargs[0]["timeout"] is None
        assert "-maxtime" not in captured_commands[0]

    @pytest.mark.asyncio
    async def test_sqlmap_none_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured_kwargs: list[dict] = []

        async def capture_runner(command, **kwargs):
            captured_kwargs.append(kwargs)
            return CommandResult(command=command, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(
            "clawpwn.modules.webscan.plugins.sqlmap.resolve_binary", lambda _: "/bin/sqlmap"
        )
        plugin = SqlmapWebScannerPlugin(command_runner=capture_runner)
        await plugin.scan("http://t", WebScanConfig())

        assert captured_kwargs[0]["timeout"] is None
