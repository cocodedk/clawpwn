"""Tests for NLI wiring of scanner plugins and timeout defaults."""

from __future__ import annotations

import pytest

from clawpwn.ai.nli.constants import VULN_CATEGORIES, VULN_CATEGORY_ALIASES
from clawpwn.ai.nli.tool_executors import EXTERNAL_TOOLS
from clawpwn.ai.nli.tools import WEB_SCAN_TOOL
from clawpwn.modules.webscan import WebScanConfig
from clawpwn.modules.webscan.runtime import CommandResult

# ---------------------------------------------------------------------------
# NLI wiring: categories, aliases, schemas, factory
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
# Timeout defaults
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
        desc = WEB_SCAN_TOOL["input_schema"]["properties"]["timeout"]["description"]
        assert "no default" in desc.lower()
        assert "run to completion" in desc.lower()


# ---------------------------------------------------------------------------
# Plugin timeout pass-through
# ---------------------------------------------------------------------------


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
