"""ConsoleApp class definition."""

from pathlib import Path

from rich.console import Console

from clawpwn.config import get_project_db_path
from clawpwn.console.completer import CommandCompleter
from clawpwn.console.history import HistoryManager
from clawpwn.console.router import InputMode, InputRouter

from .command_mixin import CommandMixin
from .help_data import HELP_TOPIC_ALIASES, HELP_TOPICS
from .help_mixin import HelpMixin
from .runtime_mixin import RuntimeMixin


class ConsoleApp(HelpMixin, CommandMixin, RuntimeMixin):
    """Interactive console for ClawPwn with CLI and NLI support."""

    HELP_TOPICS: dict[str, str] = HELP_TOPICS
    HELP_TOPIC_ALIASES: dict[str, str] = HELP_TOPIC_ALIASES

    def __init__(self, project_dir: Path | None = None) -> None:
        self.project_dir = project_dir
        self.session = None
        self.nli = None
        self.console = Console()
        self.history = HistoryManager()
        self.completer = CommandCompleter()
        self.router = InputRouter(mode=InputMode.AUTO)
        self.running = False
        self.restart_requested = False
        self.debug_enabled = False

        if not project_dir:
            return

        db_path = get_project_db_path(project_dir)
        if db_path and db_path.exists():
            from clawpwn.modules.session import SessionManager

            self.session = SessionManager(db_path)

        from clawpwn.ai.nli import NaturalLanguageInterface

        self.nli = NaturalLanguageInterface(project_dir)
