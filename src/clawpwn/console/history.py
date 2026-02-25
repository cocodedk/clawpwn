"""Persistent command history for the ClawPwn console."""

from pathlib import Path

from prompt_toolkit.history import FileHistory


class HistoryManager:
    """Manages persistent command history for the console."""

    def __init__(self) -> None:
        self.history_dir = Path.home() / ".clawpwn"
        self.history_file = self.history_dir / "console_history"
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self._file_history = FileHistory(str(self.history_file))

    def get_history(self) -> FileHistory:
        """Return the FileHistory instance for use with PromptSession."""
        return self._file_history

    def get_recent(self, n: int = 20) -> list[str]:
        """Get the last n commands from history for display.

        Supports FileHistory format: entries prefixed with '+ ' and separated
        by blank lines. Other non-empty lines are also accepted for backwards
        compatibility.
        """
        lines: list[str] = []
        try:
            if not self.history_file.exists():
                return []
            content = self.history_file.read_text()
            for line in content.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                if line.startswith("+ "):
                    lines.append(line[2:].strip())
                elif not line.startswith("+"):
                    lines.append(line)
            return lines[-n:] if len(lines) > n else lines
        except OSError:
            return []
