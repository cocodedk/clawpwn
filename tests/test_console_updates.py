"""Tests for console router and completer updates."""

from clawpwn.console.completer import CommandCompleter
from clawpwn.console.router import InputRouter


class TestConsoleRouterUpdates:
    """Test console router updates for new commands."""

    def test_new_commands_in_cli_commands(self):
        """Test that new commands are in CLI_COMMANDS."""
        router = InputRouter()

        assert "fingerprint" in router.CLI_COMMANDS
        assert "search" in router.CLI_COMMANDS
        assert "credtest" in router.CLI_COMMANDS

    def test_fingerprint_command_routing(self):
        """Test fingerprint command routing."""
        router = InputRouter()

        route_type, _ = router.route("fingerprint https://example.com")
        assert route_type == "nli"

    def test_search_command_routing(self):
        """Test search command routing."""
        router = InputRouter()

        route_type, _ = router.route("search phpMyAdmin exploit")
        assert route_type == "nli"

    def test_credtest_command_routing(self):
        """Test credtest command routing."""
        router = InputRouter()

        route_type, _ = router.route("credtest https://example.com/login")
        assert route_type == "nli"


class TestCommandCompleterUpdates:
    """Test command completer updates for new commands."""

    def test_new_commands_in_completer(self):
        """Test that new commands are in completer."""
        completer = CommandCompleter()

        assert "fingerprint" in completer.COMMANDS
        assert "search" in completer.COMMANDS
        assert "credtest" in completer.COMMANDS

    def test_search_command_options(self):
        """Test search command options."""
        completer = CommandCompleter()

        assert "--max-results" in completer.COMMANDS["search"]

    def test_credtest_command_options(self):
        """Test credtest command options."""
        completer = CommandCompleter()

        assert "--app-hint" in completer.COMMANDS["credtest"]

    def test_fingerprint_command_no_options(self):
        """Test fingerprint command has no options."""
        completer = CommandCompleter()

        assert completer.COMMANDS["fingerprint"] == []


class TestAvailabilityUpdates:
    """Test availability.py updates."""

    def test_hydra_in_external_tools(self):
        """Test that hydra was added to EXTERNAL_TOOLS."""
        from clawpwn.ai.nli.tool_executors.availability import EXTERNAL_TOOLS

        assert "hydra" in EXTERNAL_TOOLS
        assert EXTERNAL_TOOLS["hydra"]["binary"] == "hydra"
        assert "install" in EXTERNAL_TOOLS["hydra"]
