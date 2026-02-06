"""Tab completion for ClawPwn console commands and options."""

from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document


class CommandCompleter(Completer):
    """Tab completion for clawpwn commands and options."""

    COMMANDS: dict[str, list[str]] = {
        "scan": [
            "--depth",
            "-d",
            "--verbose",
            "-v",
            "--scanner",
            "-s",
            "--parallel",
            "-p",
            "--auto",
        ],
        "lan": [
            "--range",
            "-r",
            "--scan-hosts",
            "--depth",
            "-d",
            "--verbose",
            "-v",
            "--scanner",
            "-s",
            "--parallel",
            "-p",
            "--verify-tcp",
            "--udp",
            "--udp-full",
            "--max-hosts",
            "--concurrency",
        ],
        "discover": [
            "--range",
            "-r",
            "--scan-hosts",
            "--depth",
            "-d",
            "--verbose",
            "-v",
            "--scanner",
            "-s",
            "--parallel",
            "-p",
            "--verify-tcp",
            "--udp",
            "--udp-full",
            "--max-hosts",
            "--concurrency",
        ],
        "target": [],
        "status": [],
        "killchain": ["--auto", "--target"],
        "report": ["--format", "--include-evidence", "--no-evidence"],
        "logs": ["--limit", "--level"],
        "config": ["show", "edit", "init", "--global"],
        "init": [],
        "version": [],
        "list-projects": [],
        "console": [],
        "interactive": [],
        "restart": [],
        "objective": ["show", "set", "clear"],
        "memory": ["show", "clear", "--limit"],
    }

    DEPTH_VALUES = ["quick", "normal", "deep"]
    SCANNER_VALUES = ["rustscan", "masscan", "nmap"]
    FORMAT_VALUES = ["html", "pdf", "json", "md"]
    LEVEL_VALUES = ["DEBUG", "INFO", "WARNING", "ERROR"]
    CONFIG_ACTIONS = ["show", "edit", "init"]
    OBJECTIVE_ACTIONS = ["show", "set", "clear"]
    MEMORY_ACTIONS = ["show", "clear"]

    def get_completions(self, document: Document, complete_event):  # noqa: D401
        """Yield completions for the current input."""
        text = document.text_before_cursor
        words = text.split()
        if text.endswith(" "):
            words.append("")

        if not words:
            for cmd in sorted(self.COMMANDS.keys()):
                yield Completion(cmd, start_position=-len(text))
            return

        first = words[0].lower()
        last_word = words[-1].lower() if words else ""
        start_position = -len(last_word) if last_word else 0

        # Completing first token: command name
        if len(words) == 1:
            for cmd in sorted(self.COMMANDS.keys()):
                if cmd.startswith(first):
                    yield Completion(cmd, start_position=-len(first))
            return

        # Completing after command: options or values
        if first not in self.COMMANDS:
            return

        options = self.COMMANDS.get(first, [])

        # Check if we're completing an option value
        prev = words[-2].lower() if len(words) >= 2 else ""
        if prev in ("--depth", "-d"):
            for v in self.DEPTH_VALUES:
                if v.startswith(last_word):
                    yield Completion(v, start_position=start_position)
            return
        if prev in ("--scanner", "-s"):
            for v in self.SCANNER_VALUES:
                if v.startswith(last_word):
                    yield Completion(v, start_position=start_position)
            return
        if prev == "--format":
            for v in self.FORMAT_VALUES:
                if v.startswith(last_word):
                    yield Completion(v, start_position=start_position)
            return
        if prev == "--level":
            for v in self.LEVEL_VALUES:
                if v.lower().startswith(last_word):
                    yield Completion(v, start_position=start_position)
            return
        if first == "config" and len(words) == 2:
            for a in self.CONFIG_ACTIONS:
                if a.startswith(last_word):
                    yield Completion(a, start_position=start_position)
            return
        if first == "objective" and len(words) == 2:
            for a in self.OBJECTIVE_ACTIONS:
                if a.startswith(last_word):
                    yield Completion(a, start_position=start_position)
            return
        if first == "memory" and len(words) == 2:
            for a in self.MEMORY_ACTIONS:
                if a.startswith(last_word):
                    yield Completion(a, start_position=start_position)
            return

        # Completing option name (e.g. scan --<TAB>)
        if last_word.startswith("-"):
            for opt in options:
                if opt.startswith(last_word):
                    yield Completion(opt, start_position=start_position)
            return

        # Suggest options that haven't been used yet
        used = {w for w in words[1:] if w.startswith("-")}
        for opt in options:
            if opt not in used and opt.startswith("-") and opt.startswith(last_word):
                yield Completion(opt, start_position=start_position)
