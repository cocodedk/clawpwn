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
        "killchain",
        "report",
        "logs",
        "config",
        "init",
        "version",
        "list-projects",
        "console",
        "interactive",
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

        # Force CLI with ! prefix
        if line.startswith("!"):
            rest = line[1:].strip()
            if not rest:
                return ("cli", [])
            return ("cli", shlex.split(rest))

        # Force NLI with ? prefix
        if line.startswith("?"):
            return ("nli", line[1:].strip())

        # Mode-specific routing
        if self.mode == InputMode.CLI:
            return ("cli", shlex.split(line))
        if self.mode == InputMode.NLI:
            return ("nli", line)

        # Auto mode: detect based on first token
        parts = line.split()
        first_word = parts[0].lower() if parts else ""
        if first_word in self.CLI_COMMANDS or line.strip().startswith("--"):
            return ("cli", shlex.split(line))
        return ("nli", line)
