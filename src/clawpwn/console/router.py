"""Input routing for CLI vs natural language in the console."""

import shlex
from enum import Enum


class InputMode(Enum):
    """How to interpret user input."""

    CLI = "cli"
    NLI = "nli"
    AUTO = "auto"


class InputRouter:
    """Routes user input to CLI or NLI based on content and mode."""

    CLI_COMMANDS = {
        "scan",
        "target",
        "status",
        "discover",
        "lan",
        "killchain",
        "report",
        "logs",
        "config",
        "init",
        "version",
        "list-projects",
        "console",
        "interactive",
        "objective",
        "memory",
    }

    def __init__(self, mode: InputMode = InputMode.AUTO) -> None:
        self.mode = mode

    def route(self, line: str) -> tuple[str, list[str] | str]:
        """
        Route a line to either CLI (argv) or NLI (raw text).

        Returns:
            ("cli", ["scan", "--depth", "deep"]) or
            ("nli", "scan the target deeply")
        """
        line = line.strip()
        if not line:
            return ("nli", "")

        def _safe_split(text: str) -> list[str]:
            try:
                return shlex.split(text)
            except ValueError:
                return text.split()

        # Force CLI with ! prefix
        if line.startswith("!"):
            rest = line[1:].strip()
            if not rest:
                return ("cli", [])
            return ("cli", _safe_split(rest))

        # Force NLI with ? prefix
        if line.startswith("?"):
            return ("nli", line[1:].strip())

        # Mode-specific routing
        if self.mode == InputMode.CLI:
            return ("cli", _safe_split(line))
        if self.mode == InputMode.NLI:
            return ("nli", line)

        # Auto mode: detect based on content
        parts = line.split()
        first_word = parts[0].lower() if parts else ""

        # Lines starting with flags are always CLI
        if line.strip().startswith("--"):
            return ("cli", _safe_split(line))

        # If first word is a CLI command, decide CLI vs NLI
        if first_word in self.CLI_COMMANDS:
            # Commands that take a single positional arg stay CLI
            # e.g. "target https://...", "status", "config set ..."
            if first_word in self._ALWAYS_CLI_COMMANDS:
                return ("cli", _safe_split(line))
            # Has flags → CLI  ("scan --depth deep")
            if len(parts) >= 2 and parts[1].startswith("-"):
                return ("cli", _safe_split(line))
            # Otherwise route to NLI for intelligent handling
            # e.g. "scan", "scan http://...", "scan for sql injection ..."
            return ("nli", line)

        return ("nli", line)

    # Commands that should always go to CLI (simple positional args, no AI needed)
    _ALWAYS_CLI_COMMANDS = {
        "target",
        "status",
        "config",
        "init",
        "version",
        "list-projects",
        "console",
        "logs",
        "report",
        "objective",
        "memory",
        "interactive",
    }
