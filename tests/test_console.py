"""Tests for the ClawPwn interactive console."""

from pathlib import Path

from prompt_toolkit.document import Document
from prompt_toolkit.history import FileHistory

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

    def test_complete_empty_suggests_commands(self) -> None:
        completions = self._get_completions("")
        assert "scan" in completions
        assert "target" in completions
        assert "status" in completions


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
                self.history_file.write_text("scan\nstatus\ntarget x\n")
                self._file_history = FileHistory(str(self.history_file))

        manager = FakeHistoryManager(tmp_path)
        recent = manager.get_recent(10)
        assert len(recent) == 3
        assert "scan" in recent
        assert "status" in recent
