"""Tests for the sqlmap web scanner plugin."""

from __future__ import annotations

import pytest

from clawpwn.modules.webscan import WebScanConfig
from clawpwn.modules.webscan.plugins.sqlmap import SqlmapWebScannerPlugin, _SqlmapRequestContext
from clawpwn.modules.webscan.runtime import CommandResult


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

    @pytest.mark.asyncio
    async def test_none_timeout_passed_through(self, monkeypatch: pytest.MonkeyPatch) -> None:
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
