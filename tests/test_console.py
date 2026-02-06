"""Tests for the ClawPwn interactive console."""

from pathlib import Path
from unittest.mock import Mock

from prompt_toolkit.document import Document
from prompt_toolkit.history import FileHistory

from clawpwn.console.app import ConsoleApp
from clawpwn.console.completer import CommandCompleter
from clawpwn.console.history import HistoryManager
from clawpwn.console.router import InputMode, InputRouter


class TestInputRouter:
    """Tests for InputRouter."""

    def test_route_cli_command_auto_mode(self) -> None:
        router = InputRouter(mode=InputMode.AUTO)
        dest, payload = router.route("scan --depth deep")
        assert dest == "cli"
        assert payload == ["scan", "--depth", "deep"]

    def test_route_nli_auto_mode(self) -> None:
        router = InputRouter(mode=InputMode.AUTO)
        dest, payload = router.route("check for vulnerabilities")
        assert dest == "nli"
        assert payload == "check for vulnerabilities"

    def test_route_force_cli_with_bang(self) -> None:
        router = InputRouter(mode=InputMode.AUTO)
        dest, payload = router.route("!status")
        assert dest == "cli"
        assert payload == ["status"]

    def test_route_force_cli_with_bang_and_args(self) -> None:
        router = InputRouter(mode=InputMode.AUTO)
        dest, payload = router.route("!scan --depth deep")
        assert dest == "cli"
        assert payload == ["scan", "--depth", "deep"]

    def test_route_force_nli_with_question(self) -> None:
        router = InputRouter(mode=InputMode.AUTO)
        dest, payload = router.route("?what is the status")
        assert dest == "nli"
        assert payload == "what is the status"

    def test_route_empty_returns_nli(self) -> None:
        router = InputRouter(mode=InputMode.AUTO)
        dest, payload = router.route("")
        assert dest == "nli"
        assert payload == ""

    def test_route_cli_mode_always_cli(self) -> None:
        router = InputRouter(mode=InputMode.CLI)
        dest, payload = router.route("hello world")
        assert dest == "cli"
        assert payload == ["hello", "world"]

    def test_route_nli_mode_always_nli(self) -> None:
        router = InputRouter(mode=InputMode.NLI)
        dest, payload = router.route("scan example.com")
        assert dest == "nli"
        assert payload == "scan example.com"

    def test_route_preserves_quoted_args(self) -> None:
        router = InputRouter(mode=InputMode.AUTO)
        dest, payload = router.route('target "https://example.com/path"')
        assert dest == "cli"
        assert payload == ["target", "https://example.com/path"]


class TestCommandCompleter:
    """Tests for CommandCompleter."""

    def _get_completions(self, text: str, position: int | None = None) -> list[str]:
        if position is None:
            position = len(text)
        doc = Document(text, cursor_position=position)
        completer = CommandCompleter()
        return [c.text for c in completer.get_completions(doc, None)]

    def test_complete_command_prefix(self) -> None:
        completions = self._get_completions("sc")
        assert "scan" in completions
        assert "status" not in completions

    def test_complete_scan_options(self) -> None:
        completions = self._get_completions("scan --de")
        assert "--depth" in completions

    def test_complete_depth_values(self) -> None:
        completions = self._get_completions("scan --depth qu")
        assert "quick" in completions

    def test_complete_scanner_values(self) -> None:
        completions = self._get_completions("scan --scanner rust")
        assert "rustscan" in completions

    def test_complete_web_tool_values(self) -> None:
        completions = self._get_completions("scan --web-tools fer")
        assert "feroxbuster" in completions

    def test_complete_empty_suggests_commands(self) -> None:
        completions = self._get_completions("")
        assert "scan" in completions
        assert "restart" in completions
        assert "target" in completions
        assert "status" in completions


class TestConsoleAppBuiltins:
    """Tests for built-in console commands."""

    def test_restart_builtin_sets_restart_flag(self) -> None:
        app = ConsoleApp(project_dir=None)
        app.running = True

        handled = app._handle_builtin("restart")

        assert handled is True
        assert app.running is False
        assert app.restart_requested is True

    def test_invoke_nli_prints_executed_command(self) -> None:
        app = ConsoleApp(project_dir=None)
        app.nli = Mock()
        app.console = Mock()
        app.nli.process_command.return_value = {
            "success": True,
            "response": "Host scan complete.",
            "execution_note": "Running host scan on 172.17.0.2 (nmap, deep, verbose).",
            "executed_command": "!scan --scanner nmap --depth deep --verbose",
        }

        app._invoke_nli("find open ports")

        app.console.print.assert_any_call(
            "[cyan]Running host scan on 172.17.0.2 (nmap, deep, verbose).[/cyan]"
        )
        app.console.print.assert_any_call(
            "[dim]CLI equivalent: !scan --scanner nmap --depth deep --verbose[/dim]"
        )
        app.console.print.assert_any_call("[green]✓[/green] Host scan complete.")

    def test_resolve_help_topic_maps_restart_alias(self) -> None:
        app = ConsoleApp(project_dir=None)
        assert app._resolve_help_topic("restart") == "console"

    def test_invoke_nli_uses_fallback_command_when_missing_metadata(self) -> None:
        app = ConsoleApp(project_dir=None)
        app.nli = Mock()
        app.console = Mock()
        app.nli.process_command.return_value = {
            "success": True,
            "response": "Host scan complete.",
            "action": "scan",
        }

        app._invoke_nli("find open ports")

        app.console.print.assert_any_call("[dim]CLI equivalent: !scan[/dim]")
        app.console.print.assert_any_call("[green]✓[/green] Host scan complete.")

    def test_invoke_nli_prints_progress_updates_when_not_streamed(self) -> None:
        app = ConsoleApp(project_dir=None)
        app.nli = Mock()
        app.console = Mock()
        app.nli.process_command.return_value = {
            "success": True,
            "response": "Done.",
            "progress_updates": ["● [nuclei] started", "✓ [nuclei] completed: 2 findings (1.2s)"],
            "progress_streamed": False,
            "action": "scan",
        }

        app._invoke_nli("scan web")

        app.console.print.assert_any_call("[dim]● [nuclei] started[/dim]")
        app.console.print.assert_any_call("[dim]✓ [nuclei] completed: 2 findings (1.2s)[/dim]")

    def test_invoke_nli_skips_progress_updates_when_already_streamed(self) -> None:
        app = ConsoleApp(project_dir=None)
        app.nli = Mock()
        app.console = Mock()
        app.nli.process_command.return_value = {
            "success": True,
            "response": "Done.",
            "progress_updates": ["● [nuclei] started"],
            "progress_streamed": True,
            "action": "scan",
        }

        app._invoke_nli("scan web")

        printed = [call.args[0] for call in app.console.print.call_args_list if call.args]
        assert "[dim]● [nuclei] started[/dim]" not in printed


class TestHistoryManager:
    """Tests for HistoryManager."""

    def test_get_history_returns_file_history(self) -> None:
        manager = HistoryManager()
        hist = manager.get_history()
        assert hist is not None

    def test_get_recent_empty_when_no_file(self, tmp_path: Path) -> None:
        # Use a temp dir for history so we don't touch real ~/.clawpwn
        class FakeHistoryManager(HistoryManager):
            def __init__(self, base: Path) -> None:
                self.history_dir = base
                self.history_file = base / "console_history"
                self.history_dir.mkdir(parents=True, exist_ok=True)
                # Empty file; FileHistory format uses "+ <command>" per entry
                self._file_history = FileHistory(str(self.history_file))

        manager = FakeHistoryManager(tmp_path)
        recent = manager.get_recent(5)
        assert recent == []

    def test_get_recent_returns_lines(self, tmp_path: Path) -> None:
        class FakeHistoryManager(HistoryManager):
            def __init__(self, base: Path) -> None:
                self.history_dir = base
                self.history_file = base / "console_history"
                self.history_dir.mkdir(parents=True, exist_ok=True)
                # FileHistory format: each entry as "+ <command>" with blank line between
                self.history_file.write_text("+ scan\n\n+ status\n\n+ target x\n")
                self._file_history = FileHistory(str(self.history_file))

        manager = FakeHistoryManager(tmp_path)
        recent = manager.get_recent(10)
        assert len(recent) == 3
        assert "scan" in recent
        assert "status" in recent
        assert "target x" in recent

    def test_get_recent_mixed_format_parses_both(self, tmp_path: Path) -> None:
        """FileHistory '+ cmd' and plain 'cmd' lines are both returned."""

        class FakeHistoryManager(HistoryManager):
            def __init__(self, base: Path) -> None:
                self.history_dir = base
                self.history_file = base / "console_history"
                self.history_dir.mkdir(parents=True, exist_ok=True)
                self.history_file.write_text("plainline\n+ prefixed\n")
                self._file_history = FileHistory(str(self.history_file))

        manager = FakeHistoryManager(tmp_path)
        recent = manager.get_recent(10)
        assert "plainline" in recent
        assert "prefixed" in recent
